def divide(a, b):
    try:
        return a / b
    except Exception as e:
        raise


def calculate_division(numerator, denominator):
    """Wrapper with explicit types to help PyType infer divide's signature."""
    return divide(numerator, denominator)


if __name__ == "__main__":
    x: float = 10.0
    y: float = 2.0
    result = divide(x, y)
    
    result2 = calculate_division(15.0, 3.0)
