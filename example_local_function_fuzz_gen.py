def divide(a: int, b: int) -> float:
    try:
        return a / b

# Comment out below if you want to see ZeroDivisionError crashes
    # except ZeroDivisionError:
    #     return 0.0
    except Exception as e:
        # re-raise anything else so the fuzzer can still find real bugs
        raise
