import itertools

def run_gate_test(gate_name, run_function, verifier, num_inputs, debug=False):
    """
    Generic test runner.
    
    Args:
        gate_name: name of the gate for (logging)
        run_function: function to run the gate
        verifier: function that computes expected output
        num_inputs: number of inputs for the gate (1, 2 or 3)
        debug: whether to enable debug logging
    """
    all_passed = True
    
    # Generate all possible input combinations
    for inputs in itertools.product([0, 1], repeat=num_inputs):
        try:
            # Run the gate with the inputs
            if num_inputs == 1:
                result = run_function(inputs[0], debug=debug)
            elif num_inputs == 2:
                result = run_function(inputs[0], inputs[1], debug=debug)
            elif num_inputs == 3:
                result = run_function(inputs[0], inputs[1], inputs[2], debug=debug)
            else:
                raise ValueError(f"Unsupported number of inputs: {num_inputs}")
            
            # Compute expected result using verifier
            expected = verifier(*inputs)
            
            if result == expected:
                print(f"Test passed for {gate_name}{inputs}")
            else:
                print(f"Test failed for {gate_name}{inputs}:")
                print(f"\tExpected: {expected}")
                print(f"\tResult: {result}")
                all_passed = False
                
        except Exception as e:
            print(f"Test error for {gate_name}{inputs}: {e}")
            all_passed = False
    
    return all_passed

def run_all_tests():
    """
    Run all test functions in this module (functions that start with 'test_').
    """
    test_functions = [name for name in globals() 
                     if name.startswith('test_') and callable(globals()[name])]
    
    print(f"Running {len(test_functions)} tests:")
    for test_func_name in test_functions:
        print(f"\n--- Running {test_func_name} ---")
        globals()[test_func_name]()
    
    print("\nAll tests have been run!")