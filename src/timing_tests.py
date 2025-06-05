from tests.flexo_tests import *
from tests.gitm_tests import *
from tests.ref import ref_sha1_round
import time
from random import randint

def time_gate_bulk(
    gate_fn, 
    gate_name: str,
    tot_trials: int = 1000000,
    input_bits: int = 2,
    expected_fn=None
) -> None:
    """
    Generic function to time gate operations over many iterations.
    
    Args:
        gate_fn: The gate function to test
        gate_name: Name for display purposes
        tot_trials: Number of iterations to run
        input_bits: Number of input bits to extract from seed
        expected_fn: Function to compute expected result (for validation)
    """
    def gate_fn_with_error_codes(seed: int) -> int:
        """
        Gate function that returns error codes like the hardware:
        0 = correct result
        2 = detected error (we assume this never happens in emulation)
        other = undetected error
        """
        # Extract inputs from seed
        inputs = [(seed >> i) & 1 for i in range(input_bits)]
        
        # Get emulated result
        result = gate_fn(*inputs, debug=False)
        
        # Validate if expected function provided
        if expected_fn:
            expected = expected_fn(*inputs)
            if result == expected:
                return 0  # Correct
            else:
                return 1  # Undetected error
        else:
            return 0  # Assume correct if no validation
    
    tot_correct_counts = 0
    tot_detected_counts = 0
    tot_error_counts = 0
    
    # Start timing
    start_time = time.perf_counter_ns()
    
    for seed in range(tot_trials):
        result = gate_fn_with_error_codes(seed)
        
        # Use exact same logic as hardware
        if result == 0:
            tot_correct_counts += 1
        elif result & 2:  # Check if bit 1 is set
            tot_detected_counts += 1
        else:
            tot_error_counts += 1
    
    # End timing
    end_time = time.perf_counter_ns()
    tot_ns = end_time - start_time
    tot_s = tot_ns / 1_000_000_000
    
    print(f"=== {gate_name} gate (emulated) ===")
    print(f"Accuracy: {(tot_correct_counts / tot_trials * 100):.5f}%, ", end="")
    print(f"Error detected: {(tot_detected_counts / tot_trials * 100):.5f}%, ", end="")
    print(f"Undetected error: {(tot_error_counts / tot_trials * 100):.5f}%")
    
    avg_s = tot_s / tot_trials
    print(f"Time usage per run: {avg_s:.9f} s")
    print(f"Total seconds: {tot_s:.6f} s")
    print(f"over {tot_trials} iterations.")

# Specific timing functions using the generic helpers
def time_flexo_and(tot_trials: int = 1000000) -> None:
    """
    Tests the timing behavior of an emulated Flexo AND gate.
    """
    time_gate_bulk(
        gate_fn=emulate_flexo_and,
        gate_name="AND",
        tot_trials=tot_trials,
        input_bits=2,
        expected_fn=lambda in1, in2: in1 and in2
    )

def time_gitm_and(tot_trials: int = 1000000) -> None:
    """
    Tests the timing behavior of an emulated GITM AND gate.
    """
    time_gate_bulk(
        gate_fn=emulate_gitm_and,
        gate_name="GITM AND",
        tot_trials=tot_trials,
        input_bits=2,
        expected_fn=lambda in1, in2: in1 and in2
    )

def time_gitm_mux(tot_trials: int = 1000000) -> None:
    """
    Tests the timing behavior of an emulated GITM MUX gate.
    """
    time_gate_bulk(
        gate_fn=emulate_gitm_mux,
        gate_name="GITM MUX",
        tot_trials=tot_trials,
        input_bits=3,
        expected_fn=lambda sel, in1, in2: in1 if sel == 0 else in2
    )

def time_flexo_sha1_round_average(num_iterations: int = 100) -> None:
    """
    Times SHA1 round emulation over multiple iterations and outputs average execution time.
    
    Args:
        num_iterations: Number of times to execute the emulation (default 100)
    """
    print(f"\n=== SHA1 Round Average Timing ({num_iterations} iterations) ===")
    
    total_time = 0.0
    correct_count = 0
    
    for i in range(num_iterations):
        # Generate random inputs for each iteration
        state = [randint(0, 0xFFFFFFFF) for _ in range(5)]
        w = randint(0, 0xFFFFFFFF)
        
        # Get reference result
        ref_output = ref_sha1_round(state, w, round_num=0)
        
        # Time the emulation
        start_time = time.perf_counter_ns()
        output, err_out = emulate_flexo_sha1_round(state, w, debug=False)
        end_time = time.perf_counter_ns()
        
        tot_ns = end_time - start_time
        tot_s = tot_ns / 1_000_000_000
        total_time += tot_s
        
        # Check correctness
        if all(output[j] == ref_output[j] for j in range(5)):
            correct_count += 1
        
        # Optionally print progress every 10 iterations
        if (i + 1) % 10 == 0:
            print(f"Completed {i + 1}/{num_iterations} iterations...")
    
    # Calculate and display results
    avg_time = total_time / num_iterations
    accuracy = (correct_count / num_iterations) * 100
    
    print(f"\n=== SHA1 Round Average Results ===")
    print(f"Total iterations: {num_iterations}")
    print(f"Correct results: {correct_count}/{num_iterations} ({accuracy:.2f}%)")
    print(f"Total execution time: {total_time:.6f} s")
    print(f"Average execution time per round: {avg_time:.9f} s")
    print(f"Average time per round (nanoseconds): {avg_time * 1_000_000_000:.2f} ns")

if __name__ == "__main__":
    # Bulk timing tests
    # print("=== Bulk Timing Tests ===")
    # time_flexo_and(tot_trials=1000)
    # print()
    # time_gitm_and(tot_trials=1000)
    # print()
    # time_gitm_mux(tot_trials=1000)
    # print()
    
    # # SHA1 round timing tests
    # print("=== SHA1 Round Timing Tests ===")
    # time_flexo_sha1_round_average(num_iterations=10)

    time_flexo_and(tot_trials=1000)