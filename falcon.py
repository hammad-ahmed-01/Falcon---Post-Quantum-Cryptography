"""
Implementation of Falcon signature scheme.
Details at: https://falcon-sign.info/
"""
from common import q
from numpy import set_printoptions
from math import sqrt
from fft import fft, ifft, sub, neg, add_fft, mul_fft
from ntt import sub_zq, mul_zq, div_zq
from ffsampling import gram, ffldl_fft, ffsampling_fft
from ntrugen import ntru_gen
from encoding import compress, decompress
from Crypto.Hash import SHAKE256
from os import urandom
from rng import ChaCha20
import sys
if sys.version_info >= (3, 4):
    from importlib import reload

set_printoptions(linewidth=200, precision=5, suppress=True)

log_degree_mapping = {
    2: 1, 4: 2, 8: 3, 16: 4,
    32: 5, 64: 6, 128: 7,
    256: 8, 512: 9, 1024: 10
}

HEAD_LENGTH = 1
SALT_BYTES = 40
SEED_BYTES = 56

FalconParameters = {
    2: {"n": 2, "sigma": 144.81, "sigmin": 1.116, "sig_bound": 101498, "sig_bytelen": 44},
    4: {"n": 4, "sigma": 146.84, "sigmin": 1.132, "sig_bound": 208714, "sig_bytelen": 47},
    8: {"n": 8, "sigma": 148.84, "sigmin": 1.148, "sig_bound": 428865, "sig_bytelen": 52},
    16: {"n": 16, "sigma": 151.78, "sigmin": 1.170, "sig_bound": 892039, "sig_bytelen": 63},
    32: {"n": 32, "sigma": 154.67, "sigmin": 1.193, "sig_bound": 1852696, "sig_bytelen": 82},
    64: {"n": 64, "sigma": 157.51, "sigmin": 1.214, "sig_bound": 3842630, "sig_bytelen": 122},
    128: {"n": 128, "sigma": 160.30, "sigmin": 1.236, "sig_bound": 7959734, "sig_bytelen": 200},
    256: {"n": 256, "sigma": 163.04, "sigmin": 1.257, "sig_bound": 16468416, "sig_bytelen": 356},
    512: {"n": 512, "sigma": 165.74, "sigmin": 1.278, "sig_bound": 34034726, "sig_bytelen": 666},
    1024: {"n": 1024, "sigma": 168.39, "sigmin": 1.298, "sig_bound": 70265242, "sig_bytelen": 1280}
}

def display_ldl_tree(tree, prefix=""):
    branch = "|______"
    link1 = "|      "
    link2 = "       "
    if len(tree) == 3:
        head = prefix + branch + str(tree[0]) if prefix else str(tree[0])
        return f"{head}\n{display_ldl_tree(tree[1], prefix + link1)}{display_ldl_tree(tree[2], prefix + link2)}"
    else:
        return prefix[:-len(branch)] + "|____> " + str(tree) + "\n"

def normalize_ldl_tree(tree, standard_deviation):
    """
    Normalize an LDL tree by adjusting the leaf nodes based on the standard deviation.
    This is used to scale the lattice vectors to a certain standard deviation, relevant in 
    cryptographic schemes.
    """
    if len(tree) == 3:
        # If the current node has children, recursively normalize both subtrees
        normalize_ldl_tree(tree[1], standard_deviation)
        normalize_ldl_tree(tree[2], standard_deviation)
    else:
        # If the current node is a leaf, normalize the vector:
        # Set the first element to the standard deviation divided by the square root of the real 
        # part of the current value
        # This operation adjusts the norm of the vector represented by the leaf
        tree[0] = standard_deviation / sqrt(tree[0].real)
        # Set the second element to zero, typically used to reset or clear the imaginary part or 
        # an auxiliary value
        tree[1] = 0


class PublicKey:
    def __init__(self, sk):
        self.n = sk.n
        self.h = sk.h
        self.hash_to_point = sk.hash_to_point
        self.signature_bound = sk.signature_bound
        self.verify = sk.verify

    def __repr__(self):
        return f"Public Key for n = {self.n}:\nh = {self.h}\nThe public key polynomial satisfies h*f = g mod (Phi, q)\n"

class SecretKey:
    def __init__(self, n, polys=None):
        self.n = n
        self.sigma = FalconParameters[n]["sigma"]
        self.sigmin = FalconParameters[n]["sigmin"]
        self.signature_bound = FalconParameters[n]["sig_bound"]
        self.sig_bytelen = FalconParameters[n]["sig_bytelen"]

        # Generate NTRU polynomials (f, g, F, G) satisfying the NTRU equation
        self.f, self.g, self.F, self.G = ntru_gen(n)

        # Build the basis B0 for the NTRU lattice
        B0 = [[self.g, neg(self.f)], [self.G, neg(self.F)]]
        self.B0 = B0

        # Calculate the Gram matrix of B0
        G0 = gram(B0)
        self.G0 = G0

        # Compute the FFT of the basis and the Gram matrix to speed up further calculations
        self.B0_fft = [[fft(elt) for elt in row] for row in B0]
        G0_fft = [[fft(elt) for elt in row] for row in G0]

        # Compute the LDL decomposition of the Gram matrix in the Fourier domain
        self.T_fft = ffldl_fft(G0_fft)

        # Normalize the LDL tree which represents the lattice basis to ensure it meets the required standard deviation
        normalize_ldl_tree(self.T_fft, self.sigma)

        # Calculate the public key h from the private key components f and g
        self.h = div_zq(self.g, self.f)

    def __repr__(self, detailed=False):
        details = f"Private Key for n = {self.n}:\nNTRU polynomials f, g, F, G satisfy fG - gF = q mod Phi\nf = {self.f}\ng = {self.g}\nF = {self.F}\nG = {self.G}\nB0 = {self.B0}\nG0 = {self.G0}"
        return details + "\nFFT Tree:\n" + display_ldl_tree(self.T_fft) if detailed else details

    def hash_to_point(self, message, salt):
        if q > (1 << 16):
            raise ValueError("Modulus is too large")
        k = (1 << 16) // q
        shake = SHAKE256.new()
        shake.update(salt)
        shake.update(message)
        hashed = [0] * self.n
        i = 0
        while i < self.n:
            two_bytes = shake.read(2)
            element = (two_bytes[0] << 8) + two_bytes[1]
            if element < k * q:
                hashed[i] = element % q
                i += 1
        return hashed

    def sample_preimage(self, point):
        point_fft = fft(point)
        [[a, b], [c, d]] = self.B0_fft
        t0_fft = [point_fft[i] * d[i] / q for i in range(self.n)]
        t1_fft = [-point_fft[i] * b[i] / q for i in range(self.n)]
        t_fft = [t0_fft, t1_fft]
        z_fft = ffsampling_fft(t_fft, self.T_fft, self.sigmin, urandom)
        v0_fft = add_fft(mul_fft(z_fft[0], a), mul_fft(z_fft[1], c))
        v1_fft = add_fft(mul_fft(z_fft[0], b), mul_fft(z_fft[1], d))
        v0 = [int(round(x)) for x in ifft(v0_fft)]
        v1 = [int(round(x)) for x in ifft(v1_fft)]
        s = [sub(point, v0), neg(v1)]
        return s

    def sign(self, message):
        """
        Generate a signature for a given message using the Falcon signature scheme.
        """
        # Generate the header for the signature, indicating the parameters used
        header = (0x30 + log_degree_mapping[self.n]).to_bytes(1, "little")
        # Generate a random salt
        salt = urandom(SALT_BYTES)
        # Hash the message with the salt to produce a point in the lattice
        hashed = self.hash_to_point(message, salt)
        
        # Attempt to generate a valid signature until successful
        while True:
            # Sample a preimage from the hashed message
            s = self.sample_preimage(hashed)
            
            # Calculate the Euclidean norm of the signature vector
            norm_sign = sum(x ** 2 for x in s[0]) + sum(x ** 2 for x in s[1])
            
            # Check if the signature is within the allowed bound
            if norm_sign <= self.signature_bound:
                # Compress the second part of the signature to save space
                enc_s = compress(s[1], self.sig_bytelen - HEAD_LENGTH - SALT_BYTES)
                
                # If compression was successful, return the complete signature
                if enc_s is not False:
                    return header + salt + enc_s

    def verify(self, message, signature):
        """
        Verify a signature against a given message.
        """
        # Extract the salt from the signature
        salt = signature[HEAD_LENGTH:HEAD_LENGTH + SALT_BYTES]
        # Extract the compressed part of the signature
        enc_s = signature[HEAD_LENGTH + SALT_BYTES:]
        # Decompress the signature component
        s1 = decompress(enc_s, self.sig_bytelen - HEAD_LENGTH - SALT_BYTES, self.n)

        # If decompression fails, the signature is invalid
        if s1 is False:
            return False

        # Hash the message with the salt to produce a point in the lattice
        hashed = self.hash_to_point(message, salt)

        # Calculate the first part of the signature from hash and the second part of the signature
        s0 = sub_zq(hashed, mul_zq(s1, self.h))
        # Normalize the coefficients of s0 to be within the range (-q/2, q/2]
        s0 = [(x + (q >> 1)) % q - (q >> 1) for x in s0]
        # Calculate the norm of the signature to check if it's within the allowed bound
        norm_sign = sum(x ** 2 for x in s0) + sum(x ** 2 for x in s1)

        # Return True if the signature is within the allowed bound, indicating it's valid
        return norm_sign <= self.signature_bound