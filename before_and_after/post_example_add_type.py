# from typing import Union

def divide(a, b) :
    try:
        return a / b

# Comment out below if you want to see ZeroDivisionError crashes
    # except ZeroDivisionError:
    #     return 0.0
    except Exception as e:
        # re-raise anything else so the fuzzer can still find real bugs
        raise


# Typed wrapper to help PyType infer types
def calculate_division(numerator: float, denominator: float) -> float:
    """Wrapper with explicit types to help PyType infer divide's signature."""
    return divide(numerator, denominator)


# Usage examples for PyType to infer types
if __name__ == "__main__":
    # Using typed variables
    x: float = 10.0
    y: float = 2.0
    result: float = divide(x, y)
    
    # Using the typed wrapper
    result2 = calculate_division(15.0, 3.0)
