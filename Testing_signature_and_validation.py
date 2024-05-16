import falcon

# Step 1: Key Generation
sk = falcon.SecretKey(8)  # use 2,4,8,16,32,62,128,256,512,1024
pk = falcon.PublicKey(sk)   # Generate the corresponding public key from the private key

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
