from datetime import datetime, timedelta, timezone
import hashlib
import logging
import os
import secrets
import uuid
from pathlib import Path
from typing import List

import bcrypt
import psycopg
from dotenv import load_dotenv
from fastapi import APIRouter, Cookie, FastAPI, HTTPException, Response, status
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, EmailStr, Field
from starlette.middleware.cors import CORSMiddleware

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

mongo_url = os.environ.get("MONGO_URL")
mongo_client = AsyncIOMotorClient(mongo_url) if mongo_url else None
mongo_db = mongo_client[os.environ["DB_NAME"]] if mongo_client else None
DATABASE_URL = os.environ["DATABASE_URL"]
SESSION_COOKIE = "carterscare_session"
SESSION_TTL = timedelta(days=7)

app = FastAPI()
api_router = APIRouter(prefix="/api")

class StatusCheck(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    client_name: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class StatusCheckCreate(BaseModel):
    client_name: str

class Credentials(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)

class AuthUser(BaseModel):
    id: str
    email: str
    name: str
    role: str | None = None

class AuthResponse(BaseModel):
    user: AuthUser


def db_connect():
    return psycopg.connect(DATABASE_URL)


def normalize_role(value: str | None) -> str | None:
    if value in {"admin", "manager", "moderator", "support_worker"}:
        return "manager" if value == "moderator" else value
    return None


def user_from_row(row) -> AuthUser:
    return AuthUser(id=row[0], name=row[1], email=row[2], role=normalize_role(row[3]))


def session_user(token: str | None) -> AuthUser:
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    with db_connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                'SELECT u.id, u.name, u.email, NULL FROM "user" u JOIN "session" s ON s."userId" = u.id WHERE s.token = %s AND s."expiresAt" > now()',
                (token,),
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
            return user_from_row(row)


@api_router.get("/")
async def root():
    return {"message": "CartersCare API"}

@api_router.post("/auth/sign-up", response_model=AuthResponse)
def sign_up(credentials: Credentials, response: Response):
    user_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    password_hash = bcrypt.hashpw(credentials.password.encode(), bcrypt.gensalt()).decode()
    try:
        with db_connect() as conn:
            with conn.cursor() as cur:
                cur.execute('INSERT INTO "user" ("id", "name", "email", "emailVerified", "createdAt", "updatedAt") VALUES (%s, %s, %s, false, %s, %s)', (user_id, credentials.email.lower(), credentials.email.lower(), now, now))
                cur.execute('INSERT INTO "account" ("id", "accountId", "providerId", "userId", "password", "createdAt", "updatedAt") VALUES (%s, %s, %s, %s, %s, %s, %s)', (str(uuid.uuid4()), user_id, "credential", user_id, password_hash, now, now))
                conn.commit()
    except psycopg.errors.UniqueViolation:
        raise HTTPException(status_code=409, detail="Unable to create account")
    token = issue_session(user_id, response)
    return {"user": {"id": user_id, "email": credentials.email.lower(), "name": credentials.email.lower(), "role": None}}

@api_router.post("/auth/sign-in", response_model=AuthResponse)
def sign_in(credentials: Credentials, response: Response):
    with db_connect() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT u.id, u.name, u.email, a.password FROM "user" u JOIN "account" a ON a."userId" = u.id WHERE lower(u.email) = lower(%s) AND a."providerId" = %s', (credentials.email, "credential"))
            row = cur.fetchone()
    if not row or not row[3] or not bcrypt.checkpw(credentials.password.encode(), row[3].encode()):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    issue_session(row[0], response)
    return {"user": {"id": row[0], "email": row[2], "name": row[1], "role": None}}

@api_router.get("/auth/session", response_model=AuthResponse)
def get_session(carterscare_session: str | None = Cookie(default=None)):
    return {"user": session_user(carterscare_session)}

@api_router.post("/auth/sign-out")
def sign_out(response: Response, carterscare_session: str | None = Cookie(default=None)):
    if carterscare_session:
        with db_connect() as conn:
            with conn.cursor() as cur:
                cur.execute('DELETE FROM "session" WHERE "token" = %s', (carterscare_session,))
                conn.commit()
    response.delete_cookie(SESSION_COOKIE, httponly=True, secure=True, samesite="lax")
    return {"ok": True}


def issue_session(user_id: str, response: Response) -> str:
    token = secrets.token_urlsafe(48)
    now = datetime.now(timezone.utc)
    with db_connect() as conn:
        with conn.cursor() as cur:
            cur.execute('INSERT INTO "session" ("id", "expiresAt", "token", "createdAt", "updatedAt", "userId") VALUES (%s, %s, %s, %s, %s, %s)', (str(uuid.uuid4()), now + SESSION_TTL, token, now, now, user_id))
            conn.commit()
    response.set_cookie(SESSION_COOKIE, token, httponly=True, secure=True, samesite="lax", max_age=int(SESSION_TTL.total_seconds()), path="/")
    return token

@api_router.post("/status", response_model=StatusCheck)
async def create_status_check(input: StatusCheckCreate):
    if not mongo_db:
        raise HTTPException(status_code=503, detail="Status storage is unavailable")
    status_obj = StatusCheck(**input.model_dump())
    await mongo_db.status_checks.insert_one(status_obj.model_dump())
    return status_obj

@api_router.get("/status", response_model=List[StatusCheck])
async def get_status_checks():
    if not mongo_db:
        return []
    rows = await mongo_db.status_checks.find({}, {"_id": 0}).sort("client_name", 1).limit(100).to_list(100)
    return [StatusCheck(**row) for row in rows]

app.include_router(api_router)
app.add_middleware(CORSMiddleware, allow_credentials=True, allow_origins=os.environ.get("CORS_ORIGINS", "http://localhost:4200").split(","), allow_methods=["GET", "POST", "OPTIONS"], allow_headers=["Content-Type"],)

@app.on_event("shutdown")
def shutdown_db_client():
    if mongo_client:
        mongo_client.close()

logging.basicConfig(level=logging.INFO)
