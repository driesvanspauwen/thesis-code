import unicorn as uc

from __future__ import annotations
from abc import ABC, abstractmethod
from typing import List, Tuple, Optional, Set, Dict

from .interfaces import CTrace, TestCase, Model, InputTaint, Instruction, ExecutionTrace, \
    TracedInstruction, TracedMemAccess, Input, Tracer, Actor, ActorMode, ActorPL, \
    RegisterOperand, FlagsOperand, MemoryOperand, TaintTrackerInterface, TargetDesc, \
    get_sandbox_addr, SANDBOX_DATA_SIZE, SANDBOX_CODE_SIZE, NotSupportedException, AgenOperand

from .config import CONF
from .util import Logger

from unicorn import Uc, UcError, UC_MEM_WRITE, UC_MEM_READ, UC_SECOND_SCALE, UC_HOOK_MEM_READ, \
    UC_HOOK_MEM_WRITE, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED


Checkpoint = Tuple[object, int, int, int]
""" context : UnicornContext, next_instruction, flags, spec_window) """

StoreLogEntry = Tuple[int, bytes]
""" store address, previous value """

UcPointer = int
""" pointer to a memory address within the Unicorn emulator instance """


class UnicornTargetDesc:
    registers: List[int]
    simd128_registers: List[int]
    barriers: List[str]
    flags_register: int
    pc_register: int
    actor_base_register: int
    sp_register: int
    reg_decode: Dict[str, int]
    reg_str_to_constant: Dict[str, int]


class MacroInterpreter:
    next_switch_target: Tuple[int, int] = (0, 0)

    def __init__(self, model: UnicornSeq):
        pass

    def interpret(self, macro: Instruction, address: int):
        pass

    def load_test_case(self, test_case: TestCase):
        pass


class UnicornModel(Model):
    """
    Base class for all Unicorn-based models.
    Defines the interface for all models.
    """
    # service objects
    LOG: Logger
    emulator: Uc
    target_desc: TargetDesc
    uc_target_desc: UnicornTargetDesc
    macro_interpreter: MacroInterpreter

    # checkpointing
    checkpoints: List[Checkpoint]
    store_logs: List[List[StoreLogEntry]]

    # speculation control
    in_speculation: bool = False
    nesting: int = 0
    speculation_window: int = 0
    previous_context = None

    def __init__(self,
                 sandbox_base: int,
                 code_start: int,):
        super().__init__(sandbox_base, code_start)
        self.LOG = Logger()

    @staticmethod
    @abstractmethod
    def instruction_hook(emulator: Uc, address: int, size: int, model) -> None:
        """
        Invoked when an instruction is executed.
        it records instruction
        """
        pass

    @abstractmethod
    def _load_input(self, input_: Input):
        """
        Load registers and memory with given input: this is architecture specific
        """
        pass

    @abstractmethod
    def _execute_test_case(self, inputs: List[Input],
                           nesting: int) -> Tuple[List[CTrace], List[InputTaint]]:
        pass

    # def trace_test_case(self, inputs, nesting) -> List[CTrace]:
    #     """
    #     Executes the test case with the inputs, and returns the corresponding contract traces
    #     """
    #     self.execution_tracing_enabled = True
    #     ctraces, _ = self._execute_test_case(inputs, nesting)
    #     self.execution_tracing_enabled = False
    #     return ctraces

    # def trace_test_case_with_taints(self, inputs, nesting):
    #     self.tainting_enabled = True
    #     self.execution_tracing_enabled = True
    #     ctraces, taints = self._execute_test_case(inputs, nesting)
    #     self.tainting_enabled = False
    #     self.execution_tracing_enabled = False
    #     return ctraces, taints

    # def dbg_get_trace_detailed(self, input_, nesting, raw: bool = False) -> List[str]:
    #     _, __ = self._execute_test_case([input_], nesting)
    #     trace = self.tracer.get_contract_trace_full()
    #     if raw:
    #         return [str(x) for x in trace]
    #     normalized_trace = []
    #     for val in trace:
    #         if self.code_start <= val and val < self.code_end:
    #             normalized_trace.append(f"pc:0x{val - self.code_start:x}")
    #         elif self.data_start < val and val < self.data_end:
    #             normalized_trace.append(f"mem:0x{val - self.sandbox_base:x}")
    #         else:
    #             normalized_trace.append(f"val:{val}")
    #     return normalized_trace

    @abstractmethod
    def reset_model(self):
        pass

    @abstractmethod
    def print_state(self, oneline: bool = False):
        pass

    @staticmethod
    @abstractmethod
    def trace_instruction(emulator: Uc, address: int, size: int, model) -> None:
        pass

    @staticmethod
    @abstractmethod
    def trace_mem_access(emulator: Uc, access: int, address: int, size: int, value: int,
                         model) -> None:
        pass

    @staticmethod
    def speculate_mem_access(emulator, access, address, size, value, model) -> None:
        pass

    @staticmethod
    def speculate_instruction(emulator: Uc, address, size, model) -> None:
        pass

    def post_execution_patch(self) -> None:
        pass

    def speculate_fault(self, errno: int) -> int:
        """
        return the address of the first speculative instruction
        return 0 if not speculation is triggered
        """
        return 0

    def checkpoint(self, emulator: Uc, next_instruction: int):
        pass

    def rollback(self) -> int:
        return 0

    @abstractmethod
    def emulate_vm_execution(self, address: int) -> None:
        """ Emulate the execution of an instruction in VM guest mode """
        # implemented by ISA-specific subclasses
        pass

    @abstractmethod
    def emulate_userspace_execution(self, address: int) -> None:
        """ Emulate the execution of an instruction in userspace mode """
        # implemented by ISA-specific subclasses
        pass


class UnicornSeq(UnicornModel):
    """
    The core model. Implements in-order execution and tracing of test cases.
    As well as that, this class implements:
     - fault handling
     - actor management
     - interpretation of macros

    This class does *not* implement speculative execution; refer to UnicornSpec for that.
    """
    # execution context
    actors_sorted: List[Actor]
    test_case: TestCase  # the test case being traced
    current_instruction: Instruction  # the instruction currently being executed
    current_actor: Actor  # the active actor
    # local_coverage: Optional[Dict[str, int]]  # local coverage for the current test case
    # initial_taints: List[str]  # initial taints for taint tracker

    # test case code
    code_start: UcPointer  # the lower bound of the code area
    code_end: UcPointer  # the upper bound of the code area
    exit_addr: UcPointer  # the address of the test case exit instruction
    fault_handler_addr: UcPointer  # the address of the fault handler

    # test case data
    main_area: UcPointer  # the base address of the main area
    faulty_area: UcPointer  # the base address of the faulty area
    reg_init_area: UcPointer  # the base address of the register initialization area
    stack_base: UcPointer  # the base address of the stack at the beginning of the test case

    # ISA-specific fields
    architecture: Tuple[int, int]  # (UC_ARCH, UC_MODE)
    flags_id: int  # the Unicorn constant corresponding to the flags register for the given ISA

    # fault handling
    handled_faults: Set[int]  # the set of fault types that do NOT terminate execution
    pending_fault_id: int = 0  # if a fault was triggered but not handled yet, its ID is stored here
    fault_mapping = {  # maps fault types to the corresponding Unicorn fault IDs
        "DE": [21],
        "DB": [10],
        "BP": [21],
        "BR": [13],
        "UD": [10],
        "PF": [12, 13],
        "GP": [6, 7],
        "assist": [12, 13],
    }
    had_arch_fault: bool = False

    def __init__(self,
                 sandbox_base: int,
                 code_start: int):
        super().__init__(sandbox_base, code_start)

        # sandbox
        self.underflow_pad_base = get_sandbox_addr(sandbox_base, "underflow_pad")
        self.main_area = get_sandbox_addr(sandbox_base, "main")
        self.faulty_area = get_sandbox_addr(sandbox_base, "faulty")
        self.reg_init_area = get_sandbox_addr(sandbox_base, "reg_init")
        self.stack_base = self.faulty_area - 8

        # taint tracking (actual values are set by ISA-specific subclasses)
        # self.initial_taints = []

        # fault handling
        self.handled_faults = set()
        for fault in CONF._handled_faults:
            if fault in self.fault_mapping:
                self.handled_faults.update(self.fault_mapping[fault])
            else:
                raise NotSupportedException(f"Fault type {fault} is not supported")

    def reset_model(self):
        self.checkpoints = []
        self.in_speculation = False
        self.speculation_window = 0
        # self.tracer.init_trace(self.emulator, self.uc_target_desc)
        # if self.tainting_enabled:
        #     self.taint_tracker = self.original_tain_tracker
        #     self.taint_tracker.reset(self.initial_taints)
        # else:
        #     self.taint_tracker = DummyTaintTracker([])
        self.pending_fault_id = 0
        self.had_arch_fault = False
        self.current_actor = self.test_case.actors["main"]

    def load_test_case(self, test_case: TestCase) -> None:
        """
        Instantiate emulator and copy the test case into the emulator's memory
        """
        self.test_case = test_case

        main_actor = test_case.actors["main"]
        assert main_actor.elf_section, f"Actor {main_actor.name} has no ELF section"
        actors = sorted(test_case.actors.values(), key=lambda a: (a.id_))
        self.actors_sorted = actors

        # read sections from the test case binary
        sections = []
        with open(test_case.obj_path, 'rb') as bin_file:
            for actor in actors:
                assert actor.elf_section, f"Actor {actor.name} has no ELF section"
                bin_file.seek(actor.elf_section.offset)
                sections.append(bin_file.read(actor.elf_section.size))

        # create a complete binary
        code = b''
        for section in sections:
            code += section
            padding = SANDBOX_CODE_SIZE - (len(section) % SANDBOX_CODE_SIZE)
            code += b'\x90' * padding  # fill with NOPs
        self.code_end = self.code_start + len(code)
        self.exit_addr = self.code_start + main_actor.elf_section.size - 1

        # sandbox data bounds
        self.data_start = get_sandbox_addr(self.sandbox_base, "start")
        self.data_end = self.sandbox_base + SANDBOX_DATA_SIZE * len(actors)

        # initialize emulator in x86-64 mode
        emulator = Uc(*self.architecture)

        try:
            # allocate memory
            emulator.mem_map(self.code_start, SANDBOX_CODE_SIZE * len(actors))
            emulator.mem_map(self.data_start, self.data_end - self.data_start)

            # write machine code to be emulated to memory
            emulator.mem_write(self.code_start, code)

            # set up callbacks
            emulator.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, self.trace_mem_access, self)
            emulator.hook_add(UC_HOOK_MEM_UNMAPPED, self.trace_mem_access, self)
            emulator.hook_add(UC_HOOK_CODE, self.instruction_hook, self)

            self.emulator = emulator

        except UcError as e:
            self.LOG.error("[UnicornModel:load_test_case] %s" % e)

        # set the fault handler address
        fh_id = self.target_desc.macro_specs["fault_handler"].type_
        for symbol in test_case.symbol_table:
            if symbol.type_ == fh_id:
                assert symbol.aid == 0, "Fault handler must be in the main actor"
                self.fault_handler_addr = symbol.offset + self.code_start
                break
        else:
            self.fault_handler_addr = self.exit_addr

        # load the test case into the macro interpreter
        self.macro_interpreter.load_test_case(test_case)

    def _execute_test_case(self, inputs: List[Input], nesting: int):
        """
        Execute the test case with the given inputs.

        The execution algorithm is as follows:
            - Load the inputs into registers and memory
            - Start emulation at self.code_start
            - For each instruction, call the tracers and emulate speculation according to
               the contract (implemented by UnicornTracer and by subclasses)
            - When a fault is triggered:
                a. If the fault ID is in self.handled_faults, jump to self.exit_addr
                a. Otherwise, throw an error
            - When a SWITCH macro is encountered, switch the active actor and jump to
               the corresponding function address
            - When self.exit_addr is reached:
                a. If self.is_speculating, rollback to the last checkpoint
                b. Otherwise, terminate execution
        """
        # assert self.tracer
        # self.nesting = nesting

        # contract_traces: List[CTrace] = []
        # execution_traces: List[ExecutionTrace] = []
        # taints = []
        # self.local_coverage = \
            # defaultdict(int) if CONF.coverage_type == "model_instructions" else None

        for index, input_ in enumerate(inputs):
            # self.LOG.dbg_model_header(index)

            self._load_input(input_)
            self.reset_model()
            start_address = self.code_start
            while True:
                self.pending_fault_id = 0

                # make sure that the actor is synchronized with the current address
                aid = (start_address - self.code_start) // SANDBOX_CODE_SIZE
                self.current_actor = self.test_case.get_actor_by_id(aid)

                # check if we're re-entering into the exit address
                if not self.in_speculation and self.exit_reached(start_address):
                    break

                # check if we've rolled back to the fault handler; if so, rollback again as
                # it indicates that rollback was supposed to terminate speculation
                if self.in_speculation and start_address == self.fault_handler_addr:
                    start_address = self.rollback()
                    continue

                # execute the test case
                try:
                    self.emulator.emu_start(
                        start_address, self.code_end, timeout=10 * UC_SECOND_SCALE)
                except UcError as e:
                    # the type annotation below is ignored because some
                    # of the packaged versions of Unicorn do not have
                    # complete type annotations
                    self.pending_fault_id = int(e.errno)  # type: ignore

                # handle faults
                if self.pending_fault_id:
                    if not self.previous_context:
                        self.LOG.error("Fault triggered without a previous context")

                    # workaround for a Unicorn bug: after catching an exception
                    # we need to restore some pre-exception context. otherwise,
                    # the emulator becomes corrupted
                    self.emulator.context_restore(self.previous_context)
                    # another workaround, specifically for flags
                    self.emulator.reg_write(self.flags_id, self.emulator.reg_read(self.flags_id))

                    start_address = self.handle_fault(self.pending_fault_id)
                    self.pending_fault_id = 0
                    if start_address and start_address != self.exit_addr:
                        continue

                # if we use one of the speculative contracts, we might have some residual simulation
                # that did not reach the spec. window by the end of simulation. Those need
                # to be rolled back
                if self.in_speculation:
                    start_address = self.rollback()
                    continue

                # otherwise, we're done with this execution
                break

            # Special Case: Execution in mismatch_check_mode
            # Instead of the contract trace, store the values of registers after execution
            if self.mismatch_check_mode:
                register_list = self.uc_target_desc.registers
                registers = register_list[:-2]  # exclude RSP and EFLAGS
                reg_values = [int(self.emulator.reg_read(reg)) for reg in registers]  # type: ignore
                self.tracer.trace = reg_values

            # store the results
            # contract_traces.append(self.tracer.produce_trace(self))
            # execution_traces.append(self.tracer.get_execution_trace())
            # taints.append(self.taint_tracker.get_taint())

        # update coverage
        # if self.local_coverage is not None:
        #     for inst_name in self.local_coverage.keys():
        #         self.instruction_coverage[inst_name] += 1

        # return contract_traces, taints

    def exit_reached(self, address) -> bool:
        return address == self.exit_addr or \
            (self.current_actor.id_ == 0 and address > self.exit_addr)

    def handle_fault(self, errno: int) -> int:
        # self.LOG.dbg_model_exception(errno, self.err_to_str(errno))

        # when a fault is triggered, CPU stores the PC and the fault type
        # on stack - this has to be mirrored at the contract level
        # self.tracer.observe_mem_access(UC_MEM_WRITE, self.stack_base, 8, errno, self)

        next_addr = self.speculate_fault(errno)
        if next_addr:
            return next_addr

        # if we're speculating, rollback regardless of the fault type
        if self.in_speculation:
            return 0

        # error on nested non-speculative faults
        if self.had_arch_fault:
            self.print_state()
            self.LOG.error(f"Nested fault {errno} {self.err_to_str(errno)}")
        self.had_arch_fault = True

        # an expected fault - terminate execution
        if errno in self.handled_faults:
            return self.fault_handler_addr

        # unexpected fault - throw an error
        self.print_state()
        self.LOG.error(f"Unexpected exception {errno} {self.err_to_str(errno)}")

    @staticmethod
    def instruction_hook(emulator: Uc, address: int, size: int, model: UnicornSeq) -> None:
        # terminate execution if the exit instruction is reached
        if model.exit_reached(address):
            emulator.emu_stop()
            return

        # preserve context and trace the instruction
        model.previous_context = model.emulator.context_save()
        aid = model.current_actor.id_
        section_start = model.code_start + SANDBOX_CODE_SIZE * aid
        model.current_instruction = model.test_case.address_map[aid][address - section_start]
        model.trace_instruction(emulator, address, size, model)

        # collect coverage
        # if model.local_coverage is not None:
        #     if not model.current_instruction.is_instrumentation:
        #         model.local_coverage[model.current_instruction.get_brief()] += 1

        # if the current instruction is a macro, interpret it
        if model.current_instruction.name == "macro":
            model.macro_interpreter.interpret(model.current_instruction, address)

        # emulate invalid opcode for certain instructions when executed in VM guest mode
        if model.current_actor.mode == ActorMode.GUEST:
            model.emulate_vm_execution(address)
        elif model.current_actor.privilege_level == ActorPL.USER:
            model.emulate_userspace_execution(address)

    # @staticmethod
    # def trace_instruction(emulator, address, size, model) -> None:
    #     model.taint_tracker.start_instruction(model.current_instruction)
    #     model.tracer.observe_instruction(address, size, model)
    #     # speculate_instruction is empty for seq, nonempty in subclasses
    #     model.speculate_instruction(emulator, address, size, model)
    #     model.post_execution_patch()

    # @staticmethod
    # def trace_mem_access(emulator, access, address: int, size, value, model):
    #     model.taint_tracker.track_memory_access(address, size, access == UC_MEM_WRITE)
    #     model.tracer.observe_mem_access(access, address, size, value, model)
    #     # speculate_mem_access is empty for seq, nonempty in subclasses
    #     model.speculate_mem_access(emulator, access, address, size, value, model)

    #     # emulate page faults
    #     if model.current_actor.privilege_level == ActorPL.USER:
    #         target_actor = (address - model.sandbox_base) // SANDBOX_DATA_SIZE
    #         if target_actor != model.current_actor.id_:
    #             model.pending_fault_id = 12
    #             model.emulator.emu_stop()

    @staticmethod
    def err_to_str(errno: int) -> str:
        if errno == uc.UC_ERR_OK:
            return "OK (UC_ERR_OK)"
        elif errno == uc.UC_ERR_NOMEM:
            return "No memory available or memory not present (UC_ERR_NOMEM)"
        elif errno == uc.UC_ERR_ARCH:
            return "Invalid/unsupported architecture (UC_ERR_ARCH)"
        elif errno == uc.UC_ERR_HANDLE:
            return "Invalid handle (UC_ERR_HANDLE)"
        elif errno == uc.UC_ERR_MODE:
            return "Invalid mode (UC_ERR_MODE)"
        elif errno == uc.UC_ERR_VERSION:
            return "Different API version between core & binding (UC_ERR_VERSION)"
        elif errno == uc.UC_ERR_READ_UNMAPPED:
            return "Invalid memory read (UC_ERR_READ_UNMAPPED)"
        elif errno == uc.UC_ERR_WRITE_UNMAPPED:
            return "Invalid memory write (UC_ERR_WRITE_UNMAPPED)"
        elif errno == uc.UC_ERR_FETCH_UNMAPPED:
            return "Invalid memory fetch (UC_ERR_FETCH_UNMAPPED)"
        elif errno == uc.UC_ERR_HOOK:
            return "Invalid hook type (UC_ERR_HOOK)"
        elif errno == uc.UC_ERR_INSN_INVALID:
            return "Invalid instruction (UC_ERR_INSN_INVALID)"
        elif errno == uc.UC_ERR_MAP:
            return "Invalid memory mapping (UC_ERR_MAP)"
        elif errno == uc.UC_ERR_WRITE_PROT:
            return "Write to write-protected memory (UC_ERR_WRITE_PROT)"
        elif errno == uc.UC_ERR_READ_PROT:
            return "Read from non-readable memory (UC_ERR_READ_PROT)"
        elif errno == uc.UC_ERR_FETCH_PROT:
            return "Fetch from non-executable memory (UC_ERR_FETCH_PROT)"
        elif errno == uc.UC_ERR_ARG:
            return "Invalid argument (UC_ERR_ARG)"
        elif errno == uc.UC_ERR_READ_UNALIGNED:
            return "Read from unaligned memory (UC_ERR_READ_UNALIGNED)"
        elif errno == uc.UC_ERR_WRITE_UNALIGNED:
            return "Write to unaligned memory (UC_ERR_WRITE_UNALIGNED)"
        elif errno == uc.UC_ERR_FETCH_UNALIGNED:
            return "Fetch from unaligned memory (UC_ERR_FETCH_UNALIGNED)"
        elif errno == uc.UC_ERR_RESOURCE:
            return "Insufficient resource (UC_ERR_RESOURCE)"
        elif errno == uc.UC_ERR_EXCEPTION:
            return "Misc. CPU exception (UC_ERR_EXCEPTION)"
        else:
            return "Unknown error code"
        

