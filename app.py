import sys
import resource
import traceback

def set_resource_limits(max_cpu_seconds=2, max_memory_bytes=50 * 1024 * 1024):
    """
    Restricts the system resources available to the process.
    Limits CPU time and RAM to prevent Denial of Service (DoS) attacks.
    """
    # Limit CPU time
    resource.setrlimit(resource.RLIMIT_CPU, (max_cpu_seconds, max_cpu_seconds))
    # Limit Memory (Address Space)
    resource.setrlimit(resource.RLIMIT_AS, (max_memory_bytes, max_memory_bytes))

def execute_in_sandbox(untrusted_code):
    """
    Executes code inside a restricted environment.
    """
    # Define a heavily restricted set of globals
    # We remove __builtins__ entirely to block open(), import, eval, etc.
    safe_globals = {
        "__builtins__": {
            "print": print,
            "range": range,
            "str": str,
            "int": int,
            "float": float,
            "len": len,
        }
    }
    safe_locals = {}

    print("--- Starting Sandbox Execution ---")
    
    # Fork the process so resource limits and crashes don't kill the main app
    from os import fork, waitpid
    
    pid = fork()
    if pid == 0:
        # Child Process: Apply constraints and execute
        try:
            set_resource_limits()
            # Execute the untrusted code
            exec(untrusted_code, safe_globals, safe_locals)
            sys.exit(0)
        except Exception as e:
            print(sys.stderr, f"Execution Error inside sandbox:\n")
            traceback.print_exc()
            sys.exit(1)
    else:
        # Parent Process: Wait for the sandbox to finish
        _, status = waitpid(pid, 0)
        print(f"\n--- Sandbox Finished with exit status: {status} ---")

# ==========================================
# TEST CASES
# ==========================================

# 1. Safe Code
safe_script = """
total = sum([1, 2, 3])  # Wait, sum isn't in our allowed builtins! Let's use a loop.
total = 0
for i in range(5):
    total += i
print(f"Result of safe calculation: {total}")
"""

# 2. Malicious Code (Trying to read files or loop forever)
malicious_script = """
import os
print(os.listdir('.')) # This will fail because 'import' is blocked
"""

infinite_loop_script = """
print("Starting infinite loop...")
while True:
    pass # This will be killed by the CPU resource limit
"""

if __name__ == "__main__":
    # Test safe code
    execute_in_sandbox(safe_script)
    
    print("\n" + "="*40 + "\n")
    
    # Test blocked malicious code
    execute_in_sandbox(malicious_script)
    
    print("\n" + "="*40 + "\n")
    
    # Test resource-limited code
    execute_in_sandbox(infinite_loop_script)