from dotenv import load_dotenv
load_dotenv()

import os
import bcrypt
import jwt
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
from motor.motor_asyncio import AsyncIOMotorClient
import uuid

MONGO_URL = os.environ["MONGO_URL"]
DB_NAME = os.environ["DB_NAME"]
JWT_SECRET = os.environ["JWT_SECRET"]
JWT_ALGO = "HS256"

client = AsyncIOMotorClient(MONGO_URL)
db = client[DB_NAME]

app = FastAPI(title="Merrymed API", version="2.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


def hash_password(p: str) -> str:
    return bcrypt.hashpw(p.encode(), bcrypt.gensalt()).decode()


def verify_password(p: str, h: str) -> bool:
    return bcrypt.checkpw(p.encode(), h.encode())


def create_token(email: str) -> str:
    payload = {"sub": email, "exp": datetime.now(timezone.utc) + timedelta(days=7), "type": "access"}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)


async def get_current_admin(request: Request) -> dict:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, "Not authenticated")
    token = auth[7:]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Invalid token")
    user = await db.users.find_one({"email": payload["sub"]}, {"_id": 0, "password_hash": 0})
    if not user or user.get("role") != "admin":
        raise HTTPException(403, "Forbidden")
    return user


# ============ Models ============
class LoginIn(BaseModel):
    email: EmailStr
    password: str


class I18nText(BaseModel):
    uz: str = ""
    ru: str = ""
    en: str = ""


class ProductIn(BaseModel):
    category: I18nText
    name: I18nText
    description: I18nText


class NewsIn(BaseModel):
    date: str
    title: I18nText
    excerpt: I18nText


class GalleryIn(BaseModel):
    title: I18nText
    image: str


class ContactForm(BaseModel):
    name: str
    email: EmailStr
    message: str


# ============ Seed ============
DEFAULT_PRODUCTS = [
    {"category": {"uz": "Tabletka", "ru": "Таблетка", "en": "Tablet"},
     "name": {"uz": "Analgetik tabletka", "ru": "Анальгетик таблетка", "en": "Analgesic tablet"},
     "description": {"uz": "Yuqori sifatli tabletka.", "ru": "Высококачественная таблетка.", "en": "High quality tablet."}},
    {"category": {"uz": "Kapsula", "ru": "Капсула", "en": "Capsule"},
     "name": {"uz": "Vitamin kapsula", "ru": "Витаминная капсула", "en": "Vitamin capsule"},
     "description": {"uz": "Faol komponentlar bilan.", "ru": "С активными компонентами.", "en": "With active components."}},
    {"category": {"uz": "Maz/Surtma", "ru": "Мазь", "en": "Ointment"},
     "name": {"uz": "Dermatologik surtma", "ru": "Дерматологическая мазь", "en": "Dermatological ointment"},
     "description": {"uz": "Tashqi qo'llash uchun.", "ru": "Для наружного применения.", "en": "For external use."}},
    {"category": {"uz": "Suspenziya", "ru": "Суспензия", "en": "Suspension"},
     "name": {"uz": "Bolalar uchun suspenziya", "ru": "Детская суспензия", "en": "Children suspension"},
     "description": {"uz": "Qulay dozalanadi.", "ru": "Удобное дозирование.", "en": "Easy dosing."}},
    {"category": {"uz": "Inyeksiya", "ru": "Инъекция", "en": "Injection"},
     "name": {"uz": "Steril inyeksiya", "ru": "Стерильная инъекция", "en": "Sterile injection"},
     "description": {"uz": "Klinik standartlarga mos.", "ru": "Соответствует стандартам.", "en": "Meets clinical standards."}},
    {"category": {"uz": "Ko'z tomchisi", "ru": "Глазные капли", "en": "Eye drops"},
     "name": {"uz": "Oftalmik tomchi", "ru": "Офтальмические капли", "en": "Ophthalmic drops"},
     "description": {"uz": "Aniq dozali va xavfsiz.", "ru": "Точная доза, безопасно.", "en": "Precise dose, safe."}},
]

DEFAULT_NEWS = [
    {"date": "2026-03-15",
     "title": {"uz": "Yangi liniya ishga tushirildi", "ru": "Запущена новая линия", "en": "New production line launched"},
     "excerpt": {"uz": "GMP asosida yangi liniya.", "ru": "Новая линия по GMP.", "en": "New GMP-based line."}},
    {"date": "2026-02-10",
     "title": {"uz": "Eksport kengaytirildi", "ru": "Расширен экспорт", "en": "Export expanded"},
     "excerpt": {"uz": "Mintaqa bozorlariga.", "ru": "На региональные рынки.", "en": "To regional markets."}},
    {"date": "2026-01-22",
     "title": {"uz": "Laboratoriya modernizatsiya", "ru": "Модернизация лаборатории", "en": "Lab modernized"},
     "excerpt": {"uz": "Yangi monitoring uskunalari.", "ru": "Новое оборудование.", "en": "New equipment."}},
]

DEFAULT_GALLERY = [
    {"title": {"uz": "Ishlab chiqarish liniyasi", "ru": "Производственная линия", "en": "Production line"}, "image": "/assets/hero1.jpg"},
    {"title": {"uz": "Steril sex", "ru": "Стерильный цех", "en": "Sterile workshop"}, "image": "/assets/hero2.jpg"},
    {"title": {"uz": "Zamonaviy uskuna", "ru": "Современное оборудование", "en": "Modern equipment"}, "image": "/assets/hero3.jpg"},
    {"title": {"uz": "Nazorat jarayoni", "ru": "Контроль качества", "en": "Quality control"}, "image": "/assets/control1.jpg"},
    {"title": {"uz": "Qadoqlash hududi", "ru": "Упаковочная зона", "en": "Packaging area"}, "image": "/assets/control2.jpg"},
]


@app.on_event("startup")
async def startup():
    await db.users.create_index("email", unique=True)
    # Seed admin
    email = os.environ["ADMIN_EMAIL"]
    pw = os.environ["ADMIN_PASSWORD"]
    existing = await db.users.find_one({"email": email})
    if not existing:
        await db.users.insert_one({
            "email": email, "password_hash": hash_password(pw),
            "role": "admin", "created_at": datetime.now(timezone.utc)
        })
    elif not verify_password(pw, existing["password_hash"]):
        await db.users.update_one({"email": email}, {"$set": {"password_hash": hash_password(pw)}})

    # Seed content
    if await db.products.count_documents({}) == 0:
        for p in DEFAULT_PRODUCTS:
            await db.products.insert_one({"id": str(uuid.uuid4()), **p, "created_at": datetime.now(timezone.utc)})
    if await db.news.count_documents({}) == 0:
        for n in DEFAULT_NEWS:
            await db.news.insert_one({"id": str(uuid.uuid4()), **n, "created_at": datetime.now(timezone.utc)})
    if await db.gallery.count_documents({}) == 0:
        for g in DEFAULT_GALLERY:
            await db.gallery.insert_one({"id": str(uuid.uuid4()), **g, "created_at": datetime.now(timezone.utc)})


# ============ Static (code-level) ============
COMPANY_STATIC = {
    "brand": "MERRYMED FARM",
    "metrics": [
        {"value": "200+", "label": {"uz": "Mahsulot nomlari", "ru": "Наименований продукции", "en": "Products"}},
        {"value": "10", "label": {"uz": "Farmakologik guruh", "ru": "Фарм. групп", "en": "Pharm. groups"}},
        {"value": "14500 m²", "label": {"uz": "Umumiy maydon", "ru": "Общая площадь", "en": "Total area"}},
        {"value": "11600 m²", "label": {"uz": "Ishlab chiqarish", "ru": "Производство", "en": "Production"}},
    ],
    "contact": {
        "address": {
            "uz": "Oʻzbekiston, Namangan viloyati, Namangan shahri, Sherbuloq MFY, Olmazor ko'chasi 1-uy.",
            "ru": "Узбекистан, Наманганская область, г. Наманган, МФЙ Шербулок, ул. Олмазор 1.",
            "en": "Uzbekistan, Namangan region, Namangan city, Sherbuloq MFY, Olmazor street 1.",
        },
        "index": "160141", "email": "info@merrymed.uz",
        "phones": [
            {"label": {"uz": "Umumiy", "ru": "Общий", "en": "General"}, "value": "+998 (69) 228 80 00"},
            {"label": {"uz": "Xalqaro bo'lim", "ru": "Межд. отдел", "en": "Intl. dept"}, "value": "+998 (69) 228 80 02"},
            {"label": {"uz": "Eksport", "ru": "Экспорт", "en": "Export"}, "value": "+998 (69) 228 79 90"},
        ],
    },
}


# ============ Public routes ============
@app.get("/")
def root():
    return {"status": "ok", "service": "Merrymed API"}


@app.get("/api/company")
async def get_company():
    return COMPANY_STATIC


@app.get("/api/contact-info")
async def get_contact_info():
    return COMPANY_STATIC["contact"]


def clean(doc):
    doc.pop("_id", None)
    return doc


@app.get("/api/products")
async def list_products():
    items = await db.products.find({}, {"_id": 0}).sort("created_at", -1).to_list(200)
    return items


@app.get("/api/news")
async def list_news():
    items = await db.news.find({}, {"_id": 0}).sort("date", -1).to_list(200)
    return items


@app.get("/api/gallery")
async def list_gallery():
    items = await db.gallery.find({}, {"_id": 0}).sort("created_at", -1).to_list(200)
    return items


@app.post("/api/contact")
async def submit_contact(form: ContactForm):
    rec = form.model_dump()
    rec["id"] = str(uuid.uuid4())
    rec["created_at"] = datetime.now(timezone.utc).isoformat()
    await db.contact_submissions.insert_one(dict(rec))
    return {"success": True, "message": "OK", "data": rec}


# ============ Auth ============
@app.post("/api/auth/login")
async def login(data: LoginIn):
    user = await db.users.find_one({"email": data.email.lower()})
    if not user or not verify_password(data.password, user["password_hash"]):
        raise HTTPException(401, "Invalid credentials")
    token = create_token(user["email"])
    return {"access_token": token, "token_type": "bearer", "user": {"email": user["email"], "role": user.get("role")}}


@app.get("/api/auth/me")
async def me(admin: dict = Depends(get_current_admin)):
    return admin


# ============ Admin CRUD ============
def _crud_routes(prefix: str, collection_name: str, model):
    @app.post(f"/api/admin/{prefix}", dependencies=[Depends(get_current_admin)])
    async def create_item(item: model):
        doc = {"id": str(uuid.uuid4()), **item.model_dump(), "created_at": datetime.now(timezone.utc)}
        await db[collection_name].insert_one(dict(doc))
        doc.pop("_id", None)
        doc["created_at"] = doc["created_at"].isoformat()
        return doc

    @app.put(f"/api/admin/{prefix}/{{item_id}}", dependencies=[Depends(get_current_admin)])
    async def update_item(item_id: str, item: model):
        res = await db[collection_name].update_one({"id": item_id}, {"$set": item.model_dump()})
        if res.matched_count == 0:
            raise HTTPException(404, "Not found")
        return {"success": True}

    @app.delete(f"/api/admin/{prefix}/{{item_id}}", dependencies=[Depends(get_current_admin)])
    async def delete_item(item_id: str):
        res = await db[collection_name].delete_one({"id": item_id})
        if res.deleted_count == 0:
            raise HTTPException(404, "Not found")
        return {"success": True}

    create_item.__name__ = f"create_{prefix}"
    update_item.__name__ = f"update_{prefix}"
    delete_item.__name__ = f"delete_{prefix}"


_crud_routes("products", "products", ProductIn)
_crud_routes("news", "news", NewsIn)
_crud_routes("gallery", "gallery", GalleryIn)


@app.get("/api/admin/contact-submissions", dependencies=[Depends(get_current_admin)])
async def admin_contact_submissions():
    items = await db.contact_submissions.find({}, {"_id": 0}).sort("created_at", -1).to_list(500)
    return items
