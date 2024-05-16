# Falcon---Post-Quantum-Cryptography
An effort to utilize opensource resources including fft, ntt and the given predefined roots of different values of n, to implement integrity and secure digital signature scheme.

# How it works
Run the testing_signature_and_validation.py file, adjust the parameter of SecretKey within the defined parameters. Also can change the message in the 'message'

# Opensource References
Project inspired by https://falcon-sign.info/<br>
Our efforts revolve around the falcon.py and ntrugen.py<br>
falcon.py implements the core of our algorithm handling keys generation, digital signature generation and validation.<br>
ntrugen.py implements the NTRU generation of polynomials that makes up our private key. Its used in the falcon.py file<br>
We acknowledge the use of materials especially the use of fft and ntt and their constants, that include the complex roots of cyclotomic polynomials<br>

# Considerations
Our project is a work in progress and at this stage, we have been successful in implementing an algorithm that successfully generates a digital signature utilizing NTRU based lattices, and successfully validates them
