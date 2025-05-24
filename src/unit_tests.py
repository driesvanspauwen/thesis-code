import sys
from emulator import MuWMEmulator
from loader import *
from gates.asm import *
from unicorn.x86_const import *
from random import randint
import struct
from gates.flexo.sha1.sha1_ref import ref_sha1_round
from tests.helper import run_gate_test, run_all_tests

from tests.asm_tests import *
from tests.flexo_tests import *
from tests.gitm_tests import *

##########################################
# ASM tests
##########################################

def test_assign_asm():
    verifier = lambda a: a
    return run_gate_test('ASSIGN', run_assign_asm, verifier, 1)

def test_and_asm():
    verifier = lambda a, b: a and b
    return run_gate_test('AND', run_and_asm, verifier, 2)

def test_or_asm():
    verifier = lambda a, b: a or b
    return run_gate_test('OR', run_or_asm, verifier, 2)

def test_not_asm():
    verifier = lambda a: not a
    return run_gate_test('NOT', run_not_asm, verifier, 1)

def test_and_or_asm():
    verifier = lambda a, b, c: (a and b) or c
    return run_gate_test('AND-OR', run_and_or_asm, verifier, 3)

##########################################
# GITM tests
##########################################

def test_assign_gitm():
    verifier = lambda a: a
    return run_gate_test('ASSIGN', run_assign_gitm, verifier, 1)

def test_and_gitm():
    verifier = lambda a, b: a and b
    return run_gate_test('AND', run_and_gitm, verifier, 2)

def test_or_gitm():
    verifier = lambda a, b: a or b
    return run_gate_test('OR', run_or_gitm, verifier, 2)

def test_not_gitm():
    verifier = lambda a: not a
    return run_gate_test('NOT', run_not_gitm, verifier, 1)

def test_nand_gitm():
    verifier = lambda a, b: not (a and b)
    return run_gate_test('NAND', run_nand_gitm, verifier, 2)

def test_mux_gitm():
    verifier = lambda a, b, sel: a if sel == 0 else b
    return run_gate_test('MUX', run_mux_gitm, verifier, 3)

##########################################
# Flexo tests
##########################################

def test_and_flexo():
    verifier = lambda a, b: a and b
    return run_gate_test('FLEXO-AND', run_and_flexo, verifier, 2)

# run_nand_gitm(1, 1, True)

##########################################
# CLI
##########################################

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python unit_tests.py <test_name>")
        print("       python unit_tests.py all (to run all tests)")
        print("Available tests:")
        # List all functions that start with 'test_'
        tests = [name for name in globals() if name.startswith('test_')]
        for test in tests:
            print(f"  - {test}")
        sys.exit(1)

    test_name = sys.argv[1]
    if test_name.lower() == 'all':
        run_all_tests()
    elif test_name in globals() and test_name.startswith('test_'):
        globals()[test_name]()  # Run the requested test
        print("Finished unit tests")
    else:
        print(f"Error: Test '{test_name}' not found")
        sys.exit(1)