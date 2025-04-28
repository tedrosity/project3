from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse, PlainTextResponse
import datetime
import jwt
import uuid
import sqlite3
import time
import asyncio
from db import init_db, get_key, get_valid_keys, create_user, get_user_by_username, log_auth_request
from utils import base64url_uint, serialize_key, deserialize_private_key
from argon2 import PasswordHasher

ph = PasswordHasher()
app = FastAPI()

init_db()

# Global rate limiter variables
request_counter = 0
current_second = int(time.time())
RATE_LIMIT = 10
lock = asyncio.Lock()

@app.post("/register")
async def register(request: Request):
    data = await request.json()
    username = data.get("username")
    email = data.get("email")

    if not username or not email:
        raise HTTPException(status_code=400, detail="Username and email are required.")

    generated_password = str(uuid.uuid4())
    try:
        create_user(username, email, generated_password)
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="Username or email already exists.")

    return JSONResponse({"password": generated_password}, status_code=201)

@app.post("/auth")
async def auth(request: Request):
    global request_counter, current_second

    now = int(time.time())

    async with lock:
        if now != current_second:
            current_second = now
            request_counter = 0

        if request_counter >= RATE_LIMIT:
            return PlainTextResponse("Too Many Requests", status_code=429)

        request_counter += 1

    params = dict(request.query_params)
    expired = 'expired' in params
    now_unix = int(datetime.datetime.utcnow().timestamp())

    data = await request.json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        raise HTTPException(status_code=400, detail="Username and password required.")

    user = get_user_by_username(username)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials.")

    user_id, db_username, db_password_hash = user

    try:
        ph.verify(db_password_hash, password)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid credentials.")

    key_row = get_key(expired, now_unix)
    if not key_row:
        raise HTTPException(status_code=500, detail="No suitable key found.")

    kid, key_pem, exp = key_row
    private_key = deserialize_private_key(key_pem)

    payload = {
        "sub": username,
        "iat": now_unix,
        "exp": exp
    }

    token = jwt.encode(
        payload,
        private_key,
        algorithm="RS256",
        headers={"kid": str(kid)}
    )

    client_ip = request.client.host
    log_auth_request(client_ip, user_id)

    return JSONResponse({"token": token})

@app.get("/.well-known/jwks.json")
async def jwks():
    now_unix = int(datetime.datetime.utcnow().timestamp())
    rows = get_valid_keys(now_unix)

    keys_list = []
    for kid, key_pem in rows:
        private_key = deserialize_private_key(key_pem)
        public_key = private_key.public_key()
        public_numbers = public_key.public_numbers()
        keys_list.append({
            "kty": "RSA",
            "kid": str(kid),
            "alg": "RS256",
            "use": "sig",
            "n": base64url_uint(public_numbers.n),
            "e": base64url_uint(public_numbers.e)
        })

    return {"keys": keys_list}
