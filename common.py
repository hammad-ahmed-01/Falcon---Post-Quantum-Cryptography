"""
Common utilities used across different modules of the Falcon implementation.
"""
# Integer modulus for Falcon calculations
q = 12 * 1024 + 1

def split(poly):
    n = len(poly)
    return [poly[2 * i] for i in range(n // 2)], [poly[2 * i + 1] for i in range(n // 2)]

def merge(poly_parts):
    f0, f1 = poly_parts
    n = 2 * len(f0)
    merged = [0] * n
    for i in range(n // 2):
        merged[2 * i], merged[2 * i + 1] = f0[i], f1[i]
    return merged

def square_norm(vector):
    return sum(x ** 2 for part in vector for x in part)
