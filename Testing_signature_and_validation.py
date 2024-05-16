import falcon

# Step 1: Key Generation
sk = falcon.SecretKey(8)  # Generate a private key with parameter n = 512
pk = falcon.PublicKey(sk)   # Generate the corresponding public key from the private key

# print('- initialize a secret key for:\n- n = 128, 256, 512, 1024,\n- phi = x ** n + 1,\n- q = 12 * 1024 + 1\n- find a preimage t of a point c (both in ( Z[x] mod (Phi,q) )**2 ) such that t*B0 = c\n- hash a message to a point of Z[x] mod (Phi,q)\n- sign a message\n- verify the signature of a message')
print("\n\n", sk,
      "\nPublic key:", pk)
# Step 2: Signing a Message
message = "Hello!"
signature = sk.sign(message.encode('utf-8'))  # Ensure the message is in bytes
print('Message: ',message)
print("\nSignature:", signature)
# Step 3: Verifying the Signature
is_valid = pk.verify(message.encode('utf-8'), signature)
print("\nSignature valid:", is_valid, '\n')
