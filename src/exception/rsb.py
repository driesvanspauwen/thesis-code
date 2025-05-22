from typing import List, Set, Tuple

class RSB:
    def __init__(self, exception_addrs: Set[int] = None):
        # Each entry is (predicted_return_addr, stack_location)
        # predicted_return_addr: The address that the RSB predicts
        # stack_location: The absolute address where the real return address is stored on the stack
        self.stack: List[Tuple[int, int]] = []

        # Set of addresses that never added to the RSB
        self.exception_addrs: Set[int] = exception_addrs or set()
    
    def add_exception_addr(self, addr: int):
        self.exception_addrs.add(addr)
    
    def remove_exception_addr(self, addr: int):
        if addr in self.exception_addrs:
            self.exception_addrs.remove(addr)
    
    def add_ret_addr(self, predicted_addr: int, stack_location: int):
        """
            predicted_addr: The predicted return address (call_addr + call_size)
            stack_location: The absolute address where this return address is stored on the stack
        """
        if predicted_addr not in self.exception_addrs:
            self.stack.append((predicted_addr, stack_location))
    
    def pop_ret_addr(self) -> Tuple[int, int]:
        if self.stack:
            return self.stack.pop()
        else:
            return (0, 0)  # Return default values if stack is empty
    
    def is_empty(self) -> bool:
        return len(self.stack) == 0
    
    def size(self) -> int:
        return len(self.stack)
    
    def get_predicted_addrs(self) -> List[int]:
        """Get just the predicted addresses for logging purposes"""
        return [addr for addr, _ in self.stack]