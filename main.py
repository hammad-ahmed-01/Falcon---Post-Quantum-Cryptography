from fastapi import FastAPI, HTTPException, Form
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from cryptography.fernet import Fernet
from falcon import PublicKey, SecretKey
from typing import Optional
import os
import hashlib
from cryptography.fernet import Fernet
import time

# User database
users = {}
# Store session tokens
sessions = {}

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")

# Initialize cryptographic keys
falcon_keys = {
    "user_sk": SecretKey(256),
    "user_pk": None
}
falcon_keys["user_pk"] = PublicKey(falcon_keys["user_sk"])

# Define the request models

class SignMessageRequest(BaseModel):
    message: str

class VerifyRequest(BaseModel):
    message: str
    signature: str

class RegisterRequest(BaseModel):
    user_id: str
    password: str

class AuthenticateRequest(BaseModel):
    user_id: str
    password: str
    auth_message: str

# Load HTML Template from file
html_template_path = os.path.join(os.path.dirname(__file__), "templates", "index.html")
with open(html_template_path, "r") as file:
    html_template = file.read()

# Routes
@app.get("/", response_class=HTMLResponse)
async def home():
    return html_template

@app.post("/sign")
async def sign_message(request: SignMessageRequest):
    sk = falcon_keys["user_sk"]
    signature = sk.sign(request.message.encode("utf-8"))
    return {"message": request.message, "signature": signature.hex()}

@app.post("/verify")
async def verify_message(request: VerifyRequest):
    pk = falcon_keys["user_pk"]
    is_valid = pk.verify(request.message.encode("utf-8"), bytes.fromhex(request.signature))
    return {"message": request.message, "is_valid": is_valid}

@app.post("/register")
async def register_user(request: RegisterRequest):
    if request.user_id in users:
        raise HTTPException(status_code=400, detail="User already exists.")
    
    # Hash the password for secure storage
    password_hash = hashlib.sha256(request.password.encode()).hexdigest()
    sk = SecretKey(256)
    users[request.user_id] = {
        "password_hash": password_hash,
        "key_pair": {
            "sk": sk,
            "pk": PublicKey(sk)
        }
    }
    return {"success": f"User {request.user_id} registered successfully."}

@app.post("/authenticate")
async def authenticate_user(request: AuthenticateRequest):
    if request.user_id not in users:
        raise HTTPException(status_code=404, detail="User not found.")

    user = users[request.user_id]
    if hashlib.sha256(request.password.encode()).hexdigest() != user["password_hash"]:
        raise HTTPException(status_code=403, detail="Authentication failed.")

    sk = user["key_pair"]["sk"]
    pk = user["key_pair"]["pk"]

    # Sign and verify the authentication message
    signature = sk.sign(request.auth_message.encode("utf-8"))
    is_valid = pk.verify(request.auth_message.encode("utf-8"), signature)

    if not is_valid:
        raise HTTPException(status_code=403, detail="Signature verification failed.")

    # Generate a session key (e.g., using Fernet or JWT)
    session_key = Fernet.generate_key().decode()
    sessions[session_key] = {
        "user_id": request.user_id,
        "expires_at": time.time() + 3600  # Session valid for 1 hour
    }

    print(f"Session key for user {request.user_id}: {session_key}")

    return {
        "message": request.auth_message,
        "is_valid": is_valid,
        "session_key": session_key
    }

@app.get("/validate-session")
async def validate_session(session_key: str):
    if session_key not in sessions:
        raise HTTPException(status_code=403, detail="Invalid or expired session key.")

    session = sessions[session_key]
    if time.time() > session["expires_at"]:
        del sessions[session_key]
        raise HTTPException(status_code=403, detail="Session expired.")

    return {"user_id": session["user_id"], "valid": True}
