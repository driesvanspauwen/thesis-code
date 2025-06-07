# About
This repo contains the source code for the master's thesis "Accurate and Scalable Emulation of Microarchitectural Weird Machines" by Dries Vanspauwen. 

The main contribution is WeMu, an emulation framework designed specifically for analyzing microarchitectural weird machines (µWMs). WeMu emulates their obfuscated computations by emulating the microarchitectural effects that µWMs rely on. It is built on top of the ISA-level Unicorn CPU emulator.

# Installation
Install the Python libraries listed in [`requirements.txt`](./requirements.txt), and you are good to go.

# Code structure
## Microarchitectural modeling
These components contribute to modeling microarchitectural effects:
- [`Cache`](./src/cache.py) Contains an model of a finite-size LRU cache and an infinite cache. The first one induces cache conflicts between microarchitectural weird registers, causing certain tests to fail.
- [`RSB`](./src/rsb.py) A simple RSB implementation.
- [`Timer`](./src/read_timer.py) An abstraction of the time-stamp counter.
- [`MuWMEmulator`](./src/emulator.py) The backbone of WeMu which actually runs binary emulations. Models transient and out-of-order execution effects and and updates the state of other microarchitectural models correctly.

## Helper components
These are helper components which are used when emulating binaries:
- [`Compiler`](./src/compiler.py) Compiles assembly snippets to binaries that can be interpreted by Unicorn.
- [`Loader`](./src/loader.py) Contains `AsmLoader` for loading assembly snippets and `ElfLoader` for loading full ELF binaries. They offer automatic (but customizable) memory setup in Unicorn. WeMu requires one of these for loading its inputs. 
- [`Logger`](./src/logger.py) Can be used to build execution traces and outputs them to designated logs.

# Testing framework
The testing framework can be utilized for testing if emulations of µWMs result in the expected output.

Unit tests can be written in [`unit_tests.py`](./src/unit_tests.py), which comes with a CLI for quickly running individual tests, classes of tests or all available tests. Write test functions with the prefix `test_` to make them available in the CLI.

We evaluated WeMu's correct implementation on µWMs from 2 papers:
- Wang, P. L., Brown, F., & Wahby, R. S. (2023, May). The ghost is the machine: Weird machines in transient execution. In 2023 IEEE Security and Privacy Workshops (SPW) (pp. 264-272). IEEE.
- Wang, P. L., Paccagnella, R., Wahby, R. S., & Brown, F. (2024). Bending microarchitectural weird machines towards practicality. In 33rd USENIX Security Symposium (USENIX Security 24) (pp. 1099-1116).

We refer to the first as GITM and the tests can be found [here](./src/tests/gitm_tests.py). We refer to the second as Flexo and the tests can be found [here](./src/tests/flexo_tests.py). We also include [tests of simple µWMs built in assembly](./src/tests/asm_tests.py), based on the implementation of GITM.