async function signMessage() {
    const message = document.getElementById("message").value;
    const response = await fetch("/sign", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify({ message })  // Ensure the key is `message`
    });
    const result = await response.json();
    document.getElementById("signature-output").innerText = JSON.stringify(result);
}

async function verifySignature() {
    const message = document.getElementById("message").value;
    const signature = prompt("Enter signature to verify:");
    const response = await fetch("/verify", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify({ message, signature })
    });
    const result = await response.json();
    document.getElementById("signature-output").innerText = JSON.stringify(result);
}

async function registerUser() {
    const user_id = document.getElementById("user_id").value;
    const password = document.getElementById("password").value;
    const response = await fetch("/register", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify({ user_id, password })
    });
    const result = await response.json();
    document.getElementById("mfa-output").innerText = JSON.stringify(result);
}

async function authenticateUser() {
    const user_id = document.getElementById("user_id").value;
    const password = document.getElementById("password").value;
    const auth_message = document.getElementById("auth_message").value;
    const response = await fetch("/authenticate", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify({ user_id, password, auth_message })
    });
    const result = await response.json();
    document.getElementById("mfa-output").innerText = JSON.stringify(result);
}