# JWKS Server with SQLite Storage and User Registration

FastAPI server:
- Stores RSA private keys encrypted with AES-GCM in SQLite
- Serves public keys at a JWKS endpoint
- Allows user registration with UUIDv4 passwords hashed with Argon2
- Authenticates users and issues JWTs
- Logs authentication requests (IP, timestamp, user ID)
- Rate-limits /auth to 10 requests/sec
## Endpoints
- POST `/register` — Create new user
- POST `/auth` — Authenticate user and return JWT
- GET `/.well-known/jwks.json` — Serve valid public keys
## Setup
```bash
pip install -r requirements.txt

# Export your AES key first!
$env:NOT_MY_KEY="super_secret_key_here"  # Windows
export NOT_MY_KEY="super_secret_key_here" # Bash/Mac/Linux

# Run server on port 8080
uvicorn app:app --reload --port 8080
```
