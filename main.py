# ================================================================
#  StudentSphere — COMPLETE BACKEND  (single file edition)
#  Tech: FastAPI + Motor (async MongoDB) + JWT + bcrypt
# ================================================================
#
#  HOW TO RUN (3 steps):
#  ----------------------
#  1. Install dependencies:
#       pip install fastapi uvicorn[standard] motor pymongo python-jose[cryptography] passlib[bcrypt] python-multipart python-dotenv pydantic-settings
#
#  2. Make sure MongoDB is running locally:
#       mongod        (in a separate terminal)
#
#  3. Start the server:
#       uvicorn main:app --reload
#
#  Then open: http://localhost:8000/docs   ← interactive API tester
#
#  OPTIONAL — create a .env file in the same folder:
#       MONGODB_URL=mongodb://localhost:27017
#       JWT_SECRET_KEY=any-long-random-string-here
#       OPENAI_API_KEY=sk-...              (only if using chatbot AI)
#       AI_PROVIDER=openai                 (openai | gemini | fallback)
# ================================================================

import os
import re
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, List
from enum import Enum

# ── FastAPI & ASGI ───────────────────────────────────────────────────────────
from fastapi import (
    FastAPI, APIRouter, Depends, HTTPException,
    UploadFile, File, Form, status
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

# ── Database (async MongoDB) ─────────────────────────────────────────────────
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId

# ── Auth & Security ──────────────────────────────────────────────────────────
from jose import JWTError, jwt
from passlib.context import CryptContext

# Use pbkdf2_sha256 for password hashing because it is built into passlib
# and does not require optional external backends like argon2 or bcrypt.
_pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

# ── Validation ───────────────────────────────────────────────────────────────
from pydantic import BaseModel, Field, field_validator
# `EmailStr` requires the `email-validator` package. If it's not installed
# allow a graceful fallback to plain `str` so the app can start without
# failing at import time; validation will be looser in that case.
try:
    # Only enable `EmailStr` if the optional `email-validator` package is installed.
    import email_validator  # type: ignore
    from pydantic import EmailStr
except Exception:
    EmailStr = str
from pydantic_settings import BaseSettings, SettingsConfigDict


# ================================================================
#  SECTION 1 — SETTINGS  (reads from .env if it exists)
# ================================================================

class Settings(BaseSettings):
    # App
    APP_NAME: str = "StudentSphere"

    # MongoDB
    MONGODB_URL: str = "mongodb://localhost:27017"
    DATABASE_NAME: str = "studentsphere_db"

    # JWT
    JWT_SECRET_KEY: str = "change-this-to-a-long-random-secret-in-production"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440   # 24 hours
    RESET_TOKEN_EXPIRE_MINUTES: int = 30

    # CORS — add your frontend URL here
    ALLOWED_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5500",
        "http://localhost:5500",
        "*",  # Remove this in production!
    ]

    # File uploads
    PROFILE_PICS_DIR: str = "uploads/profile_pics"
    FILES_DIR: str = "uploads/files"
    MAX_FILE_SIZE_MB: int = 10

    # AI Chatbot
    AI_PROVIDER: str = "fallback"   # "openai" | "gemini" | "fallback"
    OPENAI_API_KEY: str = ""
    GEMINI_API_KEY: str = ""

    model_config = SettingsConfigDict(env_file=str(Path(__file__).resolve().parent / ".env"), extra="ignore")

settings = Settings()

# Ensure upload directories exist on startup
os.makedirs(settings.PROFILE_PICS_DIR, exist_ok=True)
os.makedirs(settings.FILES_DIR, exist_ok=True)


# ================================================================
#  SECTION 2 — DATABASE  (Motor async connection)
# ================================================================

_mongo_client: AsyncIOMotorClient = None
_db = None

async def connect_db():
    global _mongo_client, _db
    _mongo_client = AsyncIOMotorClient(settings.MONGODB_URL)
    _db = _mongo_client[settings.DATABASE_NAME]
    print(f"✅ Connected to MongoDB → {settings.DATABASE_NAME}")

async def close_db():
    if _mongo_client:
        _mongo_client.close()
        print("🔌 MongoDB disconnected")

# Collection helpers — call these inside route handlers
def col_users():    return _db["users"]
def col_chats():    return _db["chat_history"]
def col_notes():    return _db["notes"]
def col_tasks():    return _db["tasks"]
def col_schedule(): return _db["schedule_events"]
def col_files():    return _db["files_metadata"]


# ================================================================
#  SECTION 3 — SECURITY  (passwords + JWT)
# ================================================================

def hash_password(plain: str) -> str:
    return _pwd_context.hash(plain)

def verify_password(plain: str, hashed: str) -> bool:
    return _pwd_context.verify(plain, hashed)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    payload = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    payload.update({"exp": expire, "type": "access"})
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)

def create_reset_token(email: str) -> str:
    expire = datetime.utcnow() + timedelta(minutes=settings.RESET_TOKEN_EXPIRE_MINUTES)
    return jwt.encode(
        {"sub": email, "exp": expire, "type": "reset"},
        settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM
    )

def decode_token(token: str, token_type: str = "access") -> Optional[str]:
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        if payload.get("type") != token_type:
            return None
        return payload.get("sub")
    except JWTError:
        return None


# ================================================================
#  SECTION 4 — AUTH DEPENDENCY  (protects routes that need login)
# ================================================================

_bearer = HTTPBearer()

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(_bearer)):
    """
    Add  `current_user = Depends(get_current_user)`  to any route
    to require a valid JWT token. Returns the full user document.
    """
    exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token. Please log in again.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    user_id = decode_token(credentials.credentials, "access")
    if not user_id:
        raise exc
    try:
        user = await col_users().find_one({"_id": ObjectId(user_id)})
    except Exception:
        raise exc
    if not user:
        raise exc
    if not user.get("is_active", True):
        raise HTTPException(status_code=403, detail="Account is disabled.")
    return user


# ================================================================
#  SECTION 5 — MONGODB DOCUMENT HELPERS
#  (build + serialize each document type)
# ================================================================

# ── User ─────────────────────────────────────────────────────────

def make_user(full_name, email, hashed_password, username="", profile_pic="", bio="", course="", year=""):
    now = datetime.utcnow()
    return {
        "full_name": full_name,
        "username": username or full_name.lower().replace(" ", "_"),
        "email": email.lower().strip(),
        "hashed_password": hashed_password,
        "profile_pic": profile_pic,
        "bio": bio,
        "course": course,
        "year": year,
        "is_active": True,
        "is_verified": False,
        "created_at": now,
        "updated_at": now,
    }

def serialize_user(u: dict) -> dict:
    return {
        "id": str(u["_id"]),
        "full_name": u.get("full_name", ""),
        "username": u.get("username", ""),
        "email": u.get("email", ""),
        "profile_pic": u.get("profile_pic", ""),
        "bio": u.get("bio", ""),
        "course": u.get("course", ""),
        "year": u.get("year", ""),
        "is_active": u.get("is_active", True),
        "is_verified": u.get("is_verified", False),
        "created_at": u["created_at"].isoformat() if u.get("created_at") else "",
        "updated_at": u["updated_at"].isoformat() if u.get("updated_at") else "",
    }

# ── Chat ─────────────────────────────────────────────────────────

def make_chat(user_id, user_message, bot_response):
    return {"user_id": user_id, "user_message": user_message,
            "bot_response": bot_response, "created_at": datetime.utcnow()}

def serialize_chat(c: dict) -> dict:
    return {
        "id": str(c["_id"]),
        "user_id": c.get("user_id", ""),
        "user_message": c.get("user_message", ""),
        "bot_response": c.get("bot_response", ""),
        "created_at": c["created_at"].isoformat() if c.get("created_at") else "",
    }

# ── Note ─────────────────────────────────────────────────────────

def make_note(user_id, title, content, color="#FFFF88"):
    now = datetime.utcnow()
    return {"user_id": user_id, "title": title, "content": content,
            "color": color, "is_pinned": False, "created_at": now, "updated_at": now}

def serialize_note(n: dict) -> dict:
    return {
        "id": str(n["_id"]),
        "user_id": n.get("user_id", ""),
        "title": n.get("title", ""),
        "content": n.get("content", ""),
        "color": n.get("color", "#FFFF88"),
        "is_pinned": n.get("is_pinned", False),
        "created_at": n["created_at"].isoformat() if n.get("created_at") else "",
        "updated_at": n["updated_at"].isoformat() if n.get("updated_at") else "",
    }

# ── Task ─────────────────────────────────────────────────────────

def make_task(user_id, title, description="", due_date=None, priority="medium", category="general"):
    now = datetime.utcnow()
    return {
        "user_id": user_id, "title": title, "description": description,
        "due_date": due_date, "priority": priority, "category": category,
        "is_completed": False, "completed_at": None,
        "created_at": now, "updated_at": now,
    }

def serialize_task(t: dict) -> dict:
    return {
        "id": str(t["_id"]),
        "user_id": t.get("user_id", ""),
        "title": t.get("title", ""),
        "description": t.get("description", ""),
        "due_date": t.get("due_date"),
        "priority": t.get("priority", "medium"),
        "category": t.get("category", "general"),
        "is_completed": t.get("is_completed", False),
        "completed_at": t["completed_at"].isoformat() if t.get("completed_at") else None,
        "created_at": t["created_at"].isoformat() if t.get("created_at") else "",
        "updated_at": t["updated_at"].isoformat() if t.get("updated_at") else "",
    }

# ── Schedule Event ────────────────────────────────────────────────

def make_event(user_id, title, description="", start_time="", end_time="",
               event_type="class", color="#4A90E2", is_recurring=False, recurrence=""):
    now = datetime.utcnow()
    return {
        "user_id": user_id, "title": title, "description": description,
        "start_time": start_time, "end_time": end_time,
        "event_type": event_type, "color": color,
        "is_recurring": is_recurring, "recurrence": recurrence,
        "created_at": now, "updated_at": now,
    }

def serialize_event(e: dict) -> dict:
    return {
        "id": str(e["_id"]),
        "user_id": e.get("user_id", ""),
        "title": e.get("title", ""),
        "description": e.get("description", ""),
        "start_time": e.get("start_time", ""),
        "end_time": e.get("end_time", ""),
        "event_type": e.get("event_type", "class"),
        "color": e.get("color", "#4A90E2"),
        "is_recurring": e.get("is_recurring", False),
        "recurrence": e.get("recurrence", ""),
        "created_at": e["created_at"].isoformat() if e.get("created_at") else "",
        "updated_at": e["updated_at"].isoformat() if e.get("updated_at") else "",
    }

# ── File Metadata ─────────────────────────────────────────────────

def make_file_doc(user_id, original_name, stored_name, file_path, file_size, file_type, category="general"):
    return {
        "user_id": user_id, "original_name": original_name,
        "stored_name": stored_name, "file_path": file_path,
        "file_url": f"/{file_path}",
        "file_size": file_size, "file_type": file_type,
        "category": category, "created_at": datetime.utcnow(),
    }

def serialize_file(f: dict) -> dict:
    return {
        "id": str(f["_id"]),
        "user_id": f.get("user_id", ""),
        "original_name": f.get("original_name", ""),
        "stored_name": f.get("stored_name", ""),
        "file_path": f.get("file_path", ""),
        "file_url": f.get("file_url", ""),
        "file_size": f.get("file_size", 0),
        "file_type": f.get("file_type", ""),
        "category": f.get("category", "general"),
        "created_at": f["created_at"].isoformat() if f.get("created_at") else "",
    }


# ================================================================
#  SECTION 6 — PYDANTIC SCHEMAS  (request body validation)
# ================================================================

# ── Auth Schemas ──────────────────────────────────────────────────

class SignupRequest(BaseModel):
    full_name: str = Field(..., min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)
    username: str = Field("", max_length=50)

    @field_validator("password")
    @classmethod
    def strong_password(cls, v):
        if not re.search(r"[A-Za-z]", v):
            raise ValueError("Password must contain at least one letter")
        if not re.search(r"\d", v):
            raise ValueError("Password must contain at least one number")
        return v

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str = Field(..., min_length=8)

# ── User Schemas ──────────────────────────────────────────────────

class UpdateProfileRequest(BaseModel):
    full_name: Optional[str] = Field(None, min_length=2, max_length=100)
    username: Optional[str] = Field(None, max_length=50)
    bio: Optional[str] = Field(None, max_length=500)
    course: Optional[str] = Field(None, max_length=100)
    year: Optional[str] = Field(None, max_length=20)

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=8)

# ── Chat Schema ───────────────────────────────────────────────────

class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=4000)

# ── Note Schemas ──────────────────────────────────────────────────

class CreateNoteRequest(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    content: str = Field("", max_length=5000)
    color: str = Field("#FFFF88", max_length=20)

class UpdateNoteRequest(BaseModel):
    title: Optional[str] = Field(None, max_length=200)
    content: Optional[str] = Field(None, max_length=5000)
    color: Optional[str] = Field(None, max_length=20)
    is_pinned: Optional[bool] = None

# ── Task Schemas ──────────────────────────────────────────────────

class PriorityEnum(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"

class CreateTaskRequest(BaseModel):
    title: str = Field(..., min_length=1, max_length=300)
    description: str = Field("", max_length=1000)
    due_date: Optional[str] = None
    priority: PriorityEnum = PriorityEnum.medium
    category: str = Field("general", max_length=50)

class UpdateTaskRequest(BaseModel):
    title: Optional[str] = Field(None, max_length=300)
    description: Optional[str] = Field(None, max_length=1000)
    due_date: Optional[str] = None
    priority: Optional[PriorityEnum] = None
    category: Optional[str] = Field(None, max_length=50)
    is_completed: Optional[bool] = None

# ── Schedule Schemas ──────────────────────────────────────────────

class EventTypeEnum(str, Enum):
    cls = "class"
    exam = "exam"
    assignment = "assignment"
    personal = "personal"
    other = "other"

class CreateEventRequest(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    description: str = Field("", max_length=1000)
    start_time: str
    end_time: str
    event_type: EventTypeEnum = EventTypeEnum.cls
    color: str = Field("#4A90E2", max_length=20)
    is_recurring: bool = False
    recurrence: str = Field("", max_length=20)

class UpdateEventRequest(BaseModel):
    title: Optional[str] = Field(None, max_length=200)
    description: Optional[str] = Field(None, max_length=1000)
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    event_type: Optional[EventTypeEnum] = None
    color: Optional[str] = Field(None, max_length=20)
    is_recurring: Optional[bool] = None
    recurrence: Optional[str] = Field(None, max_length=20)


# ================================================================
#  SECTION 7 — AI PROVIDER  (swappable chatbot backend)
# ================================================================

async def get_ai_response(user_message: str, history: list = None) -> str:
    """
    Central function — routes to the right AI provider based on settings.
    To switch providers: change AI_PROVIDER in your .env file.
    """
    provider = settings.AI_PROVIDER.lower()

    if provider == "openai" and settings.OPENAI_API_KEY:
        return await _call_openai(user_message, history or [])
    elif provider == "gemini" and settings.GEMINI_API_KEY:
        return await _call_gemini(user_message, history or [])
    else:
        return _demo_response(user_message)

async def _call_openai(message: str, history: list) -> str:
    try:
        from openai import AsyncOpenAI
        client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY)
        messages = [{"role": "system", "content":
            "You are StudyBot, a helpful AI assistant for students. Be concise and encouraging."}]
        messages.extend(history)
        messages.append({"role": "user", "content": message})
        response = await client.chat.completions.create(
            model="gpt-3.5-turbo", messages=messages, max_tokens=800, temperature=0.7)
        return response.choices[0].message.content
    except ImportError:
        return "❌ OpenAI not installed. Run: pip install openai"
    except Exception as e:
        return f"OpenAI error: {str(e)}"

async def _call_gemini(message: str, history: list) -> str:
    try:
        import google.generativeai as genai
        genai.configure(api_key=settings.GEMINI_API_KEY)
        model = genai.GenerativeModel("gemini-pro")
        chat = model.start_chat(history=[
            {"role": "user", "parts": h["content"]} if h["role"] == "user" else {"role": "model", "parts": h["content"]}
            for h in history
        ])
        response = chat.send_message(message)
        return response.text
    except ImportError:
        return "❌ Gemini not installed. Run: pip install google-generativeai"
    except Exception as e:
        return f"Gemini error: {str(e)}"

def _demo_response(message: str) -> str:
    """Shown when no AI provider is configured. Great for testing."""
    responses = {
        "hello": "👋 Hey! I'm StudyBot. I'm in demo mode right now — add your API key in .env to enable real AI!",
        "help":  "📚 I can help you study, explain concepts, create summaries, and manage your schedule!",
    }
    lower = message.lower()
    for key, val in responses.items():
        if key in lower:
            return val
    return (f"🤖 StudyBot (demo mode) received: '{message}'. "
            "Set AI_PROVIDER=openai and OPENAI_API_KEY in your .env to get real AI responses!")


# ================================================================
#  SECTION 8 — ROUTE HANDLERS
#  Each section = one feature of StudentSphere
# ================================================================

# ── Router instances ──────────────────────────────────────────────
r_auth      = APIRouter(prefix="/api/auth",      tags=["🔐 Auth"])
r_users     = APIRouter(prefix="/api/users",     tags=["👤 Users"])
r_chat      = APIRouter(prefix="/api/chat",      tags=["🤖 Chatbot"])
r_notes     = APIRouter(prefix="/api/notes",     tags=["📝 Notes"])
r_tasks     = APIRouter(prefix="/api/tasks",     tags=["✅ Tasks"])
r_schedule  = APIRouter(prefix="/api/schedule",  tags=["📅 Schedule"])
r_files     = APIRouter(prefix="/api/files",     tags=["📁 Files"])
r_analytics = APIRouter(prefix="/api/analytics", tags=["📊 Analytics"])


# ─────────────────────────────────────────────────────────────────
#  AUTH ROUTES  (/api/auth/...)
# ─────────────────────────────────────────────────────────────────

@r_auth.post("/signup")
async def signup(data: SignupRequest):
    """Register a new account. Returns token + user profile."""
    existing = await col_users().find_one({"email": data.email.lower().strip()})
    if existing:
        raise HTTPException(400, "An account with this email already exists.")

    if data.username:
        taken = await col_users().find_one({"username": data.username.lower()})
        if taken:
            raise HTTPException(400, "This username is already taken.")

    doc = make_user(data.full_name, data.email, hash_password(data.password), data.username)
    result = await col_users().insert_one(doc)
    doc["_id"] = result.inserted_id
    token = create_access_token({"sub": str(result.inserted_id)})
    return {"access_token": token, "token_type": "bearer", "user": serialize_user(doc)}


@r_auth.post("/login")
async def login(data: LoginRequest):
    """Log in with email + password. Returns JWT token."""
    user = await col_users().find_one({"email": data.email.lower().strip()})
    err = HTTPException(401, "Incorrect email or password.")
    if not user or not verify_password(data.password, user["hashed_password"]):
        raise err
    if not user.get("is_active", True):
        raise HTTPException(403, "Account is disabled.")
    token = create_access_token({"sub": str(user["_id"])})
    return {"access_token": token, "token_type": "bearer", "user": serialize_user(user)}


@r_auth.post("/forgot-password")
async def forgot_password(data: ForgotPasswordRequest):
    """Generate a password reset token. In production, email this to the user."""
    user = await col_users().find_one({"email": data.email.lower().strip()})
    if not user:
        # Always return success (prevents email enumeration)
        return {"message": "If this email is registered, a reset link has been sent."}
    token = create_reset_token(data.email)
    # TODO: send email with token. For now, return it directly (dev only!).
    return {"message": "Reset token generated.", "reset_token": token}


@r_auth.post("/reset-password")
async def reset_password(data: ResetPasswordRequest):
    """Set a new password using a valid reset token."""
    email = decode_token(data.token, "reset")
    if not email:
        raise HTTPException(400, "Reset token is invalid or expired. Request a new one.")
    user = await col_users().find_one({"email": email.lower()})
    if not user:
        raise HTTPException(404, "User not found.")
    await col_users().update_one(
        {"_id": user["_id"]},
        {"$set": {"hashed_password": hash_password(data.new_password), "updated_at": datetime.utcnow()}}
    )
    return {"message": "Password reset successfully. You can now log in."}


@r_auth.delete("/delete-account")
async def delete_account(me=Depends(get_current_user)):
    """Delete the current authenticated user's account and all related data."""
    user_id = str(me["_id"])
    await col_users().delete_one({"_id": me["_id"]})
    await col_chats().delete_many({"user_id": user_id})
    await col_notes().delete_many({"user_id": user_id})
    await col_tasks().delete_many({"user_id": user_id})
    await col_schedule().delete_many({"user_id": user_id})
    await col_files().delete_many({"user_id": user_id})
    return {"message": "Account deleted successfully."}


# ─────────────────────────────────────────────────────────────────
#  USER PROFILE ROUTES  (/api/users/...)
# ─────────────────────────────────────────────────────────────────

@r_users.get("/me")
async def get_profile(me=Depends(get_current_user)):
    """Get the logged-in user's profile."""
    return serialize_user(me)


@r_users.put("/me")
async def update_profile(data: UpdateProfileRequest, me=Depends(get_current_user)):
    """Update name, username, bio, course, or year."""
    fields = {k: v for k, v in data.dict().items() if v is not None}
    if not fields:
        raise HTTPException(400, "No fields to update.")
    fields["updated_at"] = datetime.utcnow()
    await col_users().update_one({"_id": me["_id"]}, {"$set": fields})
    updated = await col_users().find_one({"_id": me["_id"]})
    return serialize_user(updated)


@r_users.post("/me/profile-pic")
async def upload_profile_pic(file: UploadFile = File(...), me=Depends(get_current_user)):
    """Upload a new profile picture (JPEG, PNG, WebP — max 10MB)."""
    allowed = ["image/jpeg", "image/png", "image/gif", "image/webp"]
    if file.content_type not in allowed:
        raise HTTPException(400, "Only JPEG, PNG, GIF, WebP images allowed.")
    content = await file.read()
    if len(content) > settings.MAX_FILE_SIZE_MB * 1024 * 1024:
        raise HTTPException(400, f"Image exceeds {settings.MAX_FILE_SIZE_MB}MB limit.")

    # Delete old profile pic from disk
    old_pic = me.get("profile_pic", "")
    if old_pic and old_pic.startswith("/uploads/"):
        old_path = old_pic.lstrip("/")
        if os.path.exists(old_path):
            os.remove(old_path)

    ext = (file.filename.rsplit(".", 1)[-1] if "." in file.filename else "jpg")
    fname = f"{uuid.uuid4().hex}.{ext}"
    path = os.path.join(settings.PROFILE_PICS_DIR, fname)
    with open(path, "wb") as f:
        f.write(content)

    pic_url = f"/uploads/profile_pics/{fname}"
    await col_users().update_one(
        {"_id": me["_id"]},
        {"$set": {"profile_pic": pic_url, "updated_at": datetime.utcnow()}}
    )
    updated = await col_users().find_one({"_id": me["_id"]})
    return serialize_user(updated)


@r_users.put("/me/change-password")
async def change_password(data: ChangePasswordRequest, me=Depends(get_current_user)):
    """Verify current password, then update to a new one."""
    if not verify_password(data.current_password, me["hashed_password"]):
        raise HTTPException(400, "Current password is incorrect.")
    await col_users().update_one(
        {"_id": me["_id"]},
        {"$set": {"hashed_password": hash_password(data.new_password), "updated_at": datetime.utcnow()}}
    )
    return {"message": "Password changed successfully."}


# ─────────────────────────────────────────────────────────────────
#  CHATBOT ROUTES  (/api/chat/...)
# ─────────────────────────────────────────────────────────────────

@r_chat.post("/")
async def send_message(data: ChatRequest, me=Depends(get_current_user)):
    """Send a message to StudyBot. Response is saved in chat history."""
    user_id = str(me["_id"])

    # Load last 10 messages for conversation context
    cursor = col_chats().find({"user_id": user_id}, sort=[("created_at", -1)], limit=10)
    recent = await cursor.to_list(10)
    recent.reverse()
    history = []
    for c in recent:
        history.append({"role": "user",      "content": c["user_message"]})
        history.append({"role": "assistant",  "content": c["bot_response"]})

    bot_reply = await get_ai_response(data.message, history)

    doc = make_chat(user_id, data.message, bot_reply)
    result = await col_chats().insert_one(doc)
    doc["_id"] = result.inserted_id
    return serialize_chat(doc)


@r_chat.get("/history")
async def get_chat_history(limit: int = 50, me=Depends(get_current_user)):
    """Retrieve chat history (oldest first)."""
    user_id = str(me["_id"])
    cursor = col_chats().find({"user_id": user_id}, sort=[("created_at", -1)], limit=limit)
    chats = await cursor.to_list(limit)
    return [serialize_chat(c) for c in reversed(chats)]


@r_chat.delete("/history")
async def clear_chat_history(me=Depends(get_current_user)):
    """Delete all chat messages for this user."""
    result = await col_chats().delete_many({"user_id": str(me["_id"])})
    return {"message": f"Deleted {result.deleted_count} messages."}


# ─────────────────────────────────────────────────────────────────
#  STICKY NOTES ROUTES  (/api/notes/...)
# ─────────────────────────────────────────────────────────────────

@r_notes.post("/")
async def create_note(data: CreateNoteRequest, me=Depends(get_current_user)):
    doc = make_note(str(me["_id"]), data.title, data.content, data.color)
    result = await col_notes().insert_one(doc)
    doc["_id"] = result.inserted_id
    return serialize_note(doc)


@r_notes.get("/")
async def get_notes(me=Depends(get_current_user)):
    """Returns all notes — pinned ones first, then newest."""
    cursor = col_notes().find(
        {"user_id": str(me["_id"])},
        sort=[("is_pinned", -1), ("updated_at", -1)]
    )
    return [serialize_note(n) for n in await cursor.to_list(500)]


@r_notes.get("/{note_id}")
async def get_note(note_id: str, me=Depends(get_current_user)):
    try:
        note = await col_notes().find_one({"_id": ObjectId(note_id), "user_id": str(me["_id"])})
    except Exception:
        raise HTTPException(400, "Invalid note ID.")
    if not note:
        raise HTTPException(404, "Note not found.")
    return serialize_note(note)


@r_notes.put("/{note_id}")
async def update_note(note_id: str, data: UpdateNoteRequest, me=Depends(get_current_user)):
    fields = {k: v for k, v in data.dict().items() if v is not None}
    if not fields:
        raise HTTPException(400, "Nothing to update.")
    fields["updated_at"] = datetime.utcnow()
    try:
        res = await col_notes().update_one(
            {"_id": ObjectId(note_id), "user_id": str(me["_id"])}, {"$set": fields})
    except Exception:
        raise HTTPException(400, "Invalid note ID.")
    if res.matched_count == 0:
        raise HTTPException(404, "Note not found.")
    note = await col_notes().find_one({"_id": ObjectId(note_id)})
    return serialize_note(note)


@r_notes.delete("/{note_id}")
async def delete_note(note_id: str, me=Depends(get_current_user)):
    try:
        res = await col_notes().delete_one({"_id": ObjectId(note_id), "user_id": str(me["_id"])})
    except Exception:
        raise HTTPException(400, "Invalid note ID.")
    if res.deleted_count == 0:
        raise HTTPException(404, "Note not found.")
    return {"message": "Note deleted."}


# ─────────────────────────────────────────────────────────────────
#  TASKS / TO-DO ROUTES  (/api/tasks/...)
# ─────────────────────────────────────────────────────────────────

@r_tasks.post("/")
async def create_task(data: CreateTaskRequest, me=Depends(get_current_user)):
    doc = make_task(str(me["_id"]), data.title, data.description,
                    data.due_date, data.priority.value, data.category)
    result = await col_tasks().insert_one(doc)
    doc["_id"] = result.inserted_id
    return serialize_task(doc)


@r_tasks.get("/")
async def get_tasks(completed: Optional[bool] = None, me=Depends(get_current_user)):
    """All tasks. Filter: ?completed=true or ?completed=false"""
    query = {"user_id": str(me["_id"])}
    if completed is not None:
        query["is_completed"] = completed
    cursor = col_tasks().find(query, sort=[("is_completed", 1), ("due_date", 1)])
    return [serialize_task(t) for t in await cursor.to_list(1000)]


@r_tasks.get("/{task_id}")
async def get_task(task_id: str, me=Depends(get_current_user)):
    try:
        task = await col_tasks().find_one({"_id": ObjectId(task_id), "user_id": str(me["_id"])})
    except Exception:
        raise HTTPException(400, "Invalid task ID.")
    if not task:
        raise HTTPException(404, "Task not found.")
    return serialize_task(task)


@r_tasks.put("/{task_id}")
async def update_task(task_id: str, data: UpdateTaskRequest, me=Depends(get_current_user)):
    fields = {k: v for k, v in data.dict().items() if v is not None}
    if "priority" in fields and hasattr(fields["priority"], "value"):
        fields["priority"] = fields["priority"].value
    if fields.get("is_completed") is True:
        fields["completed_at"] = datetime.utcnow()
    elif fields.get("is_completed") is False:
        fields["completed_at"] = None
    fields["updated_at"] = datetime.utcnow()
    try:
        res = await col_tasks().update_one(
            {"_id": ObjectId(task_id), "user_id": str(me["_id"])}, {"$set": fields})
    except Exception:
        raise HTTPException(400, "Invalid task ID.")
    if res.matched_count == 0:
        raise HTTPException(404, "Task not found.")
    task = await col_tasks().find_one({"_id": ObjectId(task_id)})
    return serialize_task(task)


@r_tasks.patch("/{task_id}/toggle")
async def toggle_task(task_id: str, me=Depends(get_current_user)):
    """Flip a task between complete ↔ incomplete in one click."""
    try:
        task = await col_tasks().find_one({"_id": ObjectId(task_id), "user_id": str(me["_id"])})
    except Exception:
        raise HTTPException(400, "Invalid task ID.")
    if not task:
        raise HTTPException(404, "Task not found.")
    now_completed = not task.get("is_completed", False)
    await col_tasks().update_one(
        {"_id": ObjectId(task_id)},
        {"$set": {
            "is_completed": now_completed,
            "completed_at": datetime.utcnow() if now_completed else None,
            "updated_at": datetime.utcnow()
        }}
    )
    updated = await col_tasks().find_one({"_id": ObjectId(task_id)})
    return serialize_task(updated)


@r_tasks.delete("/{task_id}")
async def delete_task(task_id: str, me=Depends(get_current_user)):
    try:
        res = await col_tasks().delete_one({"_id": ObjectId(task_id), "user_id": str(me["_id"])})
    except Exception:
        raise HTTPException(400, "Invalid task ID.")
    if res.deleted_count == 0:
        raise HTTPException(404, "Task not found.")
    return {"message": "Task deleted."}


# ─────────────────────────────────────────────────────────────────
#  SCHEDULE / CALENDAR ROUTES  (/api/schedule/...)
# ─────────────────────────────────────────────────────────────────

@r_schedule.post("/")
async def create_event(data: CreateEventRequest, me=Depends(get_current_user)):
    doc = make_event(str(me["_id"]), data.title, data.description,
                     data.start_time, data.end_time, data.event_type.value,
                     data.color, data.is_recurring, data.recurrence)
    result = await col_schedule().insert_one(doc)
    doc["_id"] = result.inserted_id
    return serialize_event(doc)


@r_schedule.get("/")
async def get_events(me=Depends(get_current_user)):
    cursor = col_schedule().find({"user_id": str(me["_id"])}, sort=[("start_time", 1)])
    return [serialize_event(e) for e in await cursor.to_list(1000)]


@r_schedule.get("/{event_id}")
async def get_event(event_id: str, me=Depends(get_current_user)):
    try:
        event = await col_schedule().find_one({"_id": ObjectId(event_id), "user_id": str(me["_id"])})
    except Exception:
        raise HTTPException(400, "Invalid event ID.")
    if not event:
        raise HTTPException(404, "Event not found.")
    return serialize_event(event)


@r_schedule.put("/{event_id}")
async def update_event(event_id: str, data: UpdateEventRequest, me=Depends(get_current_user)):
    fields = {k: v for k, v in data.dict().items() if v is not None}
    if "event_type" in fields and hasattr(fields["event_type"], "value"):
        fields["event_type"] = fields["event_type"].value
    fields["updated_at"] = datetime.utcnow()
    try:
        res = await col_schedule().update_one(
            {"_id": ObjectId(event_id), "user_id": str(me["_id"])}, {"$set": fields})
    except Exception:
        raise HTTPException(400, "Invalid event ID.")
    if res.matched_count == 0:
        raise HTTPException(404, "Event not found.")
    event = await col_schedule().find_one({"_id": ObjectId(event_id)})
    return serialize_event(event)


@r_schedule.delete("/{event_id}")
async def delete_event(event_id: str, me=Depends(get_current_user)):
    try:
        res = await col_schedule().delete_one({"_id": ObjectId(event_id), "user_id": str(me["_id"])})
    except Exception:
        raise HTTPException(400, "Invalid event ID.")
    if res.deleted_count == 0:
        raise HTTPException(404, "Event not found.")
    return {"message": "Event deleted."}


# ─────────────────────────────────────────────────────────────────
#  FILE STORAGE ROUTES  (/api/files/...)
# ─────────────────────────────────────────────────────────────────

ALLOWED_FILE_TYPES = [
    "application/pdf", "image/jpeg", "image/png", "image/gif", "image/webp",
    "text/plain", "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.ms-powerpoint",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/vnd.ms-excel",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/zip",
]

@r_files.post("/upload")
async def upload_file(
    file: UploadFile = File(...),
    category: str = Form("general"),
    me=Depends(get_current_user)
):
    """Upload a file. Stored on disk; metadata saved in MongoDB."""
    if file.content_type not in ALLOWED_FILE_TYPES:
        raise HTTPException(400, "File type not allowed.")
    content = await file.read()
    if len(content) > settings.MAX_FILE_SIZE_MB * 1024 * 1024:
        raise HTTPException(400, f"File exceeds {settings.MAX_FILE_SIZE_MB}MB limit.")

    user_id = str(me["_id"])
    ext = (file.filename.rsplit(".", 1)[-1] if "." in file.filename else "bin")
    stored_name = f"{uuid.uuid4().hex}.{ext}"
    save_dir = os.path.join(settings.FILES_DIR, user_id)
    os.makedirs(save_dir, exist_ok=True)
    file_path = os.path.join(save_dir, stored_name)

    with open(file_path, "wb") as f:
        f.write(content)

    doc = make_file_doc(user_id, file.filename, stored_name, file_path,
                        len(content), file.content_type, category)
    result = await col_files().insert_one(doc)
    doc["_id"] = result.inserted_id
    return serialize_file(doc)


@r_files.get("/")
async def list_files(me=Depends(get_current_user)):
    """List all files uploaded by this user."""
    cursor = col_files().find({"user_id": str(me["_id"])}, sort=[("created_at", -1)])
    return [serialize_file(f) for f in await cursor.to_list(500)]


@r_files.delete("/{file_id}")
async def delete_file(file_id: str, me=Depends(get_current_user)):
    """Delete file from disk and remove its metadata."""
    try:
        fdoc = await col_files().find_one({"_id": ObjectId(file_id), "user_id": str(me["_id"])})
    except Exception:
        raise HTTPException(400, "Invalid file ID.")
    if not fdoc:
        raise HTTPException(404, "File not found.")
    if os.path.exists(fdoc["file_path"]):
        os.remove(fdoc["file_path"])
    await col_files().delete_one({"_id": ObjectId(file_id)})
    return {"message": f"'{fdoc['original_name']}' deleted."}


# ─────────────────────────────────────────────────────────────────
#  ANALYTICS ROUTES  (/api/analytics/...)
# ─────────────────────────────────────────────────────────────────

@r_analytics.get("/")
async def get_analytics(me=Depends(get_current_user)):
    """Aggregated dashboard stats across all features."""
    uid = str(me["_id"])
    now = datetime.utcnow()
    week_ago  = now - timedelta(days=7)
    month_ago = now - timedelta(days=30)

    total_tasks     = await col_tasks().count_documents({"user_id": uid})
    completed_tasks = await col_tasks().count_documents({"user_id": uid, "is_completed": True})
    overdue_tasks   = await col_tasks().count_documents({
        "user_id": uid, "is_completed": False,
        "due_date": {"$lt": now.strftime("%Y-%m-%d")}
    })
    tasks_this_week = await col_tasks().count_documents({
        "user_id": uid, "is_completed": True, "completed_at": {"$gte": week_ago}
    })

    priority_cursor = col_tasks().aggregate([
        {"$match": {"user_id": uid, "is_completed": False}},
        {"$group": {"_id": "$priority", "count": {"$sum": 1}}}
    ])
    priority_data = await priority_cursor.to_list(10)

    total_notes  = await col_notes().count_documents({"user_id": uid})
    pinned_notes = await col_notes().count_documents({"user_id": uid, "is_pinned": True})
    total_chats  = await col_chats().count_documents({"user_id": uid})
    chats_month  = await col_chats().count_documents({"user_id": uid, "created_at": {"$gte": month_ago}})
    total_files  = await col_files().count_documents({"user_id": uid})

    size_agg = await col_files().aggregate([
        {"$match": {"user_id": uid}},
        {"$group": {"_id": None, "total": {"$sum": "$file_size"}}}
    ]).to_list(1)
    storage_mb = round((size_agg[0]["total"] if size_agg else 0) / (1024 * 1024), 2)

    upcoming = await col_schedule().count_documents({
        "user_id": uid, "start_time": {"$gte": now.isoformat()}
    })

    return {
        "tasks": {
            "total": total_tasks,
            "completed": completed_tasks,
            "pending": total_tasks - completed_tasks,
            "overdue": overdue_tasks,
            "completed_this_week": tasks_this_week,
            "completion_rate": round(completed_tasks / total_tasks * 100, 1) if total_tasks else 0,
            "priority_breakdown": {p["_id"]: p["count"] for p in priority_data},
        },
        "notes":    {"total": total_notes, "pinned": pinned_notes},
        "chat":     {"total_messages": total_chats, "messages_this_month": chats_month},
        "files":    {"total_files": total_files, "storage_used_mb": storage_mb},
        "schedule": {"upcoming_events": upcoming},
        "generated_at": now.isoformat(),
    }


# ================================================================
#  SECTION 9 — APP SETUP  (wire everything together)
# ================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    await connect_db()
    try:
        yield
    finally:
        await close_db()

app = FastAPI(
    title="StudentSphere API",
    description="Complete backend for the StudentSphere student productivity dashboard 🎓",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# CORS — allow frontend to talk to this backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve uploaded files as static URLs (e.g. /uploads/profile_pics/abc.jpg)
os.makedirs("uploads", exist_ok=True)
app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")

# Register all routers
app.include_router(r_auth)
app.include_router(r_users)
app.include_router(r_chat)
app.include_router(r_notes)
app.include_router(r_tasks)
app.include_router(r_schedule)
app.include_router(r_files)
app.include_router(r_analytics)

# Health check
@app.get("/", tags=["Health"])
async def root():
    return {"message": "StudentSphere API is running 🎓", "version": "1.0.0"}

@app.get("/health", tags=["Health"])
async def health():
    return {"status": "ok"}


if __name__ == "__main__":
    # When executed as a script (`python main.py`) the module search path
    # may not include the package parent directory which can cause
    # `import StudentSphere` to fail. Run Uvicorn with the `app` object
    # directly to avoid that problem. Use the module path only as a
    # fallback.
    import uvicorn
    # Run the server programmatically using Server to avoid any forking
    # or auto-reloader side-effects that can cause the process to exit
    # immediately on some Windows setups.
    print("→ Starting Uvicorn server (programmatic run) on 127.0.0.1:8001")
    try:
        config = uvicorn.Config(app=app, host="127.0.0.1", port=8001, log_level="info", reload=False)
        server = uvicorn.Server(config)
        server.run()
        print("→ Uvicorn.run returned — server stopped")
    except Exception as e:
        print("Uvicorn startup failed:", e)
        # Fallback: attempt to run via import string
        try:
            uvicorn.run("StudentSphere.main:app", host="127.0.0.1", port=8001, reload=False)
        except Exception as e2:
            print("Fallback uvicorn run also failed:", e2)