"""
Implementation of NTRU polynomial generation
"""
from fft import fft, ifft, add_fft, mul_fft, adj_fft, div_fft
from fft import add, mul, div, adj
from ntt import ntt
from common import square_norm
from samplerz import samplerz

# Modulus used in NTRU calculations
q = 12 * 1024 + 1

def poly_multiply_karatsuba(a, b, n):
    if n == 1:
        return [a[0] * b[0], 0]
    else:
        mid = n // 2
        a0, a1 = a[:mid], a[mid:]
        b0, b1 = b[:mid], b[mid:]
        sum_a = [a0[i] + a1[i] for i in range(mid)]
        sum_b = [b0[i] + b1[i] for i in range(mid)]
        product_a0b0 = poly_multiply_karatsuba(a0, b0, mid)
        product_a1b1 = poly_multiply_karatsuba(a1, b1, mid)
        product_sum = poly_multiply_karatsuba(sum_a, sum_b, mid)
        for i in range(n):
            product_sum[i] -= product_a0b0[i] + product_a1b1[i]
        result = [0] * (2 * n)
        for i in range(n):
            result[i] += product_a0b0[i]
            result[i + n] += product_a1b1[i]
            result[i + mid] += product_sum[i]
        return result

def karatsuba_reduction(a, b):
    n = len(a)
    ab = poly_multiply_karatsuba(a, b, n)
    return [ab[i] - ab[i + n] for i in range(n)]

def conjugate_galois(a):
    n = len(a)
    return [((-1) ** i) * a[i] for i in range(n)]

def norm_field(a):
    n_half = len(a) // 2
    even_terms = [a[2 * i] for i in range(n_half)]
    odd_terms = [a[2 * i + 1] for i in range(n_half)]
    squared_even = karatsuba_reduction(even_terms, even_terms)
    squared_odd = karatsuba_reduction(odd_terms, odd_terms)
    result = squared_even[:]
    for i in range(n_half - 1):
        result[i + 1] -= squared_odd[i]
    result[0] += squared_odd[n_half - 1]
    return result

def poly_lift(a):
    n = len(a)
    result = [0] * (2 * n)
    for i in range(n):
        result[2 * i] = a[i]
    return result

def bitsize_value(a):
    abs_a = abs(a)
    bits = 0
    while abs_a:
        bits += 8
        abs_a >>= 8
    return bits

def babai_reduction(f, g, F, G):
    n = len(f)
    adjusted_size = max(53, bitsize_value(min(f)), bitsize_value(max(f)), bitsize_value(min(g)), bitsize_value(max(g)))
    adjusted_f = [x >> (adjusted_size - 53) for x in f]
    adjusted_g = [x >> (adjusted_size - 53) for x in g]
    fft_f = fft(adjusted_f)
    fft_g = fft(adjusted_g)
    while True:
        current_size = max(53, bitsize_value(min(F)), bitsize_value(max(F)), bitsize_value(min(G)), bitsize_value(max(G)))
        if current_size < adjusted_size:
            break
        adjusted_F = [x >> (current_size - 53) for x in F]
        adjusted_G = [x >> (current_size - 53) for x in G]
        fft_F = fft(adjusted_F)
        fft_G = fft(adjusted_G)
        denominator_fft = add_fft(mul_fft(fft_f, adj_fft(fft_f)), mul_fft(fft_g, adj_fft(fft_g)))
        numerator_fft = add_fft(mul_fft(fft_F, adj_fft(fft_f)), mul_fft(fft_G, adj_fft(fft_g)))
        k_fft = div_fft(numerator_fft, denominator_fft)
        k = [int(round(x)) for x in ifft(k_fft)]
        if all(x == 0 for x in k):
            break
        poly_k_f = karatsuba_reduction(f, k)
        poly_k_g = karatsuba_reduction(g, k)
        for i in range(n):
            F[i] -= poly_k_f[i] << (current_size - adjusted_size)
            G[i] -= poly_k_g[i] << (current_size - adjusted_size)
    return F, G

def extended_gcd(a, b):
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b != 0:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0

def ntru_solve(f, g):
    n = len(f)
    if n == 1:
        d, u, v = extended_gcd(f[0], g[0])
        if d != 1:
            raise ValueError("GCD not 1")
        return [-q * v], [q * u]
    else:
        norm_f = norm_field(f)
        norm_g = norm_field(g)
        Fp, Gp = ntru_solve(norm_f, norm_g)
        lifted_F = poly_lift(Fp)
        lifted_G = poly_lift(Gp)
        conjugated_g = conjugate_galois(g)
        conjugated_f = conjugate_galois(f)
        F = karatsuba_reduction(lifted_F, conjugated_g)
        G = karatsuba_reduction(lifted_G, conjugated_f)
        F, G = babai_reduction(f, g, F, G)
        return F, G

def gs_norm(f, g, q):
    norm_fg = square_norm([f, g])
    product_fg = add(mul(f, adj(f)), mul(g, adj(g)))
    Ft = div(adj(g), product_fg)
    Gt = div(adj(f), product_fg)
    norm_FG = (q ** 2) * square_norm([Ft, Gt])
    return max(norm_fg, norm_FG)

def gen_poly(n):
    sigma_fg = 1.43300980528773
    assert(n < 4096)
    raw_samples = [samplerz(0, sigma_fg, sigma_fg - 0.001) for _ in range(4096)]
    polynomial = [0] * n
    k = 4096 // n
    for i in range(n):
        polynomial[i] = sum(raw_samples[i * k + j] for j in range(k))
    return polynomial

def generate_ntru(n):
    while True:
        f = gen_poly(n)
        g = gen_poly(n)
        if gs_norm(f, g, q) > (1.17 ** 2) * q:
            continue
        f_ntt = ntt(f)
        if any(elem == 0 for elem in f_ntt):
            continue
        try:
            F, G = ntru_solve(f, g)
            F = [int(x) for x in F]
            G = [int(x) for x in G]
            return f, g, F, G
        except ValueError:
            continue

def ntru_gen(n):
    """
    Implement the algorithm 5 (NTRUGen) of Falcon's documentation.
    At the end of the function, polynomials f, g, F, G in Z[x]/(x ** n + 1)
    are output, which verify f * G - g * F = q mod (x ** n + 1).
    """
    while True:
        f = gen_poly(n)
        g = gen_poly(n)
        if gs_norm(f, g, q) > (1.17 ** 2) * q:
            continue
        f_ntt = ntt(f)
        if any((elem == 0) for elem in f_ntt):
            continue
        try:
            F, G = ntru_solve(f, g)
            F = [int(coef) for coef in F]
            G = [int(coef) for coef in G]
            return f, g, F, G
        # If the NTRU equation cannot be solved, a ValueError is raised
        # In this case, we start again
        except ValueError:
            continue
