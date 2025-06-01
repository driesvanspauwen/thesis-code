# gem5 Evaluatino

## Timing
Script:
```python
import time

start_time = time.time()

# Rest of script...

def exit_handler():
    """Handle exit events - simulation should exit after checkpoint"""
    end_time = time.time()
    total_time = end_time - start_time
    print(f"=== Simulation completed after checkpoint ===")
    print(f"=== Total simulation time: {total_time:.2f} seconds ===")
    yield False
```

Output:
=== Total simulation time: 1963.04 seconds ===

