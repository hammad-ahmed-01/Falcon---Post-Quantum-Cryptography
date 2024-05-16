"""
Sampler for generating discrete Gaussian random variables as required for Falcon.
"""
from math import floor
from os import urandom

# Upper limit for sigma values
MAX_SIGMA = 1.8205
INVERSE_2SIGMA2 = 1 / (2 * (MAX_SIGMA ** 2))

# Precision for the reverse cumulative distribution table
PREC_RCDT = 72

# Constants for logarithmic and exponential calculations
LN2 = 0.69314718056
INVERSE_LN2 = 1.44269504089

# Reverse cumulative distribution table for a near half-Gaussian distribution
REVERSE_CDT = [
    3024686241123004913666, 1564742784480091954050, 636254429462080897535,
    199560484645026482916, 47667343854657281903, 8595902006365044063,
    1163297957344668388, 117656387352093658, 8867391802663976,
    496969357462633, 20680885154299, 638331848991, 14602316184,
    247426747, 3104126, 28824, 198, 1
]

# Polynomial coefficients for approximating exp(-x)
POLY_COEFFS = [
    0x00000004741183A3, 0x00000036548CFC06, 0x0000024FDCBF140A,
    0x0000171D939DE045, 0x0000D00CF58F6F84, 0x000680681CF796E3,
    0x002D82D8305B0FEA, 0x011111110E066FD0, 0x0555555555070F00,
    0x155555555581FF00, 0x400000000002B400, 0x7FFFFFFFFFFF4800,
    0x8000000000000000
]

def base_sampler(random_bytes=urandom):
    u = int.from_bytes(random_bytes(PREC_RCDT >> 3), "little")
    z0 = 0
    for threshold in REVERSE_CDT:
        z0 += int(u < threshold)
    return z0

def approx_exp(x, scaling_factor):
    y, z = POLY_COEFFS[0], int(x * (1 << 63))
    for coeff in POLY_COEFFS[1:]:
        y = coeff - ((z * y) >> 63)
    z = int(scaling_factor * (1 << 63)) << 1
    y = (z * y) >> 63
    return y

def bernoulli_exp(x, scaling_factor, random_bytes=urandom):
    shift = int(x * INVERSE_LN2)
    remainder = x - shift * LN2
    shift = min(shift, 63)
    z = (approx_exp(remainder, scaling_factor) - 1) >> shift
    for i in range(56, -8, -8):
        p = int.from_bytes(random_bytes(1), "little")
        w = p - ((z >> i) & 0xFF)
        if w != 0:
            break
    return w < 0

def samplerz(mu, sigma, sigma_min, random_bytes=urandom):
    integer_part = int(floor(mu))
    fractional_part = mu - integer_part
    variance_scale = 1 / (2 * sigma * sigma)
    scaling_factor = sigma_min / sigma
    while True:
        z0 = base_sampler(random_bytes)
        sign_bit = int.from_bytes(random_bytes(1), "little") & 1
        z = sign_bit + (2 * sign_bit - 1) * z0
        x = ((z - fractional_part) ** 2) * variance_scale
        x -= (z0 ** 2) * INVERSE_2SIGMA2
        if bernoulli_exp(x, scaling_factor, random_bytes):
            return z + integer_part
