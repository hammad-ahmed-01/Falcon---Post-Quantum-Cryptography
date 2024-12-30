import hashlib
import json
from cryptography.fernet import Fernet
from falcon import PublicKey, SecretKey

class MFAIntegration:
    def __init__(self):
        self.keys = {}
        self.secret_key = SecretKey(256)  # FALCON Secret Key
        self.public_key = PublicKey(self.secret_key)

    def register_user(self, user_id, password):
        """
        Register a user by creating cryptographic keys and storing a password.
        """
        if user_id in self.keys:
            return "User already exists."

        # Hash the password for secure storage
        password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()

        # Save keys and password hash
        self.keys[user_id] = {
            "public_key": self.public_key,
            "private_key": self.secret_key,
            "password_hash": password_hash,
        }
        return "User registered successfully."

    def authenticate_user(self, user_id, password, message):
        """
        Authenticate the user by validating the password and cryptographic signature.
        """
        if user_id not in self.keys:
            return "User not found."

        # Validate password
        password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
        if self.keys[user_id]["password_hash"] != password_hash:
            return "Password authentication failed."

        # Generate and validate signature
        message_bytes = message.encode('utf-8')
        signature = self.keys[user_id]["private_key"].sign(message_bytes)
        is_valid = self.keys[user_id]["public_key"].verify(message_bytes, signature)

        return "Authentication successful." if is_valid else "Signature verification failed."

    def generate_token(self, user_id):
        """
        Generate a secure token after successful authentication.
        """
        if user_id not in self.keys:
            return None

        # Example token generation
        payload = {
            "user_id": user_id,
            "timestamp": "2023-12-30T12:00:00Z",
        }
        token = Fernet.generate_key()
        cipher = Fernet(token)
        encrypted_payload = cipher.encrypt(json.dumps(payload).encode('utf-8'))
        return encrypted_payload

# Usage Example
if __name__ == "__main__":
    mfa_system = MFAIntegration()

    # Register a user
    print(mfa_system.register_user("user123", "securepassword"))

    # Authenticate user
    message = "Login request"
    print(mfa_system.authenticate_user("user123", "securepassword", message))

    # Generate a session token
    print(mfa_system.generate_token("user123"))
