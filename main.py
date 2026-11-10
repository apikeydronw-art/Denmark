import hashlib
import hmac
import logging
import os
import secrets
import smtplib
import sqlite3
import ssl
import uuid
from email.message import EmailMessage
from typing import Literal
from urllib.parse import parse_qs, urlsplit

import stripe
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, Field

app = FastAPI(
    title="CyberGuard Security Engine",
    description="Cloud-backed FastAPI server på GitHub Codespaces",
    version="2.0.0"
)

# Wix Velo requests are public; credentials are not used with wildcard origins.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# SQLite Database Setup
DB_FILE = os.getenv("DB_FILE", "cyberguard.db")
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY")
SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = os.getenv("SMTP_PORT", "587")
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SENDER_EMAIL = os.getenv("SENDER_EMAIL", "")
settings_security = HTTPBasic(auto_error=False)
logger = logging.getLogger(__name__)

def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS licenses (
                license_key TEXT PRIMARY KEY,
                customer_email TEXT NOT NULL,
                asset_name TEXT NOT NULL,
                order_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        license_columns = {row[1] for row in conn.execute("PRAGMA table_info(licenses)")}
        if "order_id" not in license_columns:
            conn.execute("ALTER TABLE licenses ADD COLUMN order_id INTEGER")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS assets (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT NOT NULL,
                category TEXT NOT NULL,
                owner_email TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        asset_columns = {row[1] for row in conn.execute("PRAGMA table_info(assets)")}
        if "price_usd" not in asset_columns:
            conn.execute("ALTER TABLE assets ADD COLUMN price_usd REAL")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS inventory (
                owner_email TEXT NOT NULL,
                asset_id TEXT NOT NULL,
                acquired_via TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (owner_email, asset_id),
                FOREIGN KEY (asset_id) REFERENCES assets(id)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS trades (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                from_email TEXT NOT NULL,
                from_asset_id TEXT NOT NULL,
                to_email TEXT NOT NULL,
                to_asset_id TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                customer_email TEXT NOT NULL,
                item_id TEXT NOT NULL,
                item_name TEXT NOT NULL,
                price_usd REAL NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending_payment',
                license_key TEXT,
                payment_reference TEXT,
                email_sent INTEGER NOT NULL DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        order_columns = {row[1] for row in conn.execute("PRAGMA table_info(orders)")}
        if "email_sent" not in order_columns:
            conn.execute("ALTER TABLE orders ADD COLUMN email_sent INTEGER NOT NULL DEFAULT 0")
        if "stripe_session_id" not in order_columns:
            conn.execute("ALTER TABLE orders ADD COLUMN stripe_session_id TEXT")
        if "checkout_url" not in order_columns:
            conn.execute("ALTER TABLE orders ADD COLUMN checkout_url TEXT")
        conn.execute(
            "UPDATE licenses SET order_id = ("
            "SELECT id FROM orders WHERE orders.license_key = licenses.license_key"
            ") WHERE order_id IS NULL AND EXISTS ("
            "SELECT 1 FROM orders WHERE orders.license_key = licenses.license_key"
            ")"
        )
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_licenses_order_id "
            "ON licenses (order_id) WHERE order_id IS NOT NULL"
        )
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_orders_stripe_session_id "
            "ON orders (stripe_session_id) WHERE stripe_session_id IS NOT NULL"
        )
        conn.execute("""
            CREATE TABLE IF NOT EXISTS lookup_verifications (
                customer_email TEXT PRIMARY KEY,
                token_hash TEXT NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                requested_at TIMESTAMP NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0
            )
        """)
        conn.execute(
            "INSERT OR IGNORE INTO inventory (owner_email, asset_id, acquired_via) "
            "SELECT lower(owner_email), id, 'custom_asset' FROM assets"
        )

init_db()

class ChatMessage(BaseModel):
    user_query: str = Field(min_length=1, max_length=2000)

class PurchaseRequest(BaseModel):
    customer_email: str = Field(min_length=3, max_length=254)
    asset_name: str = Field(min_length=1, max_length=120)


class CheckoutRequest(BaseModel):
    customer_email: str = Field(min_length=3, max_length=254)
    item_name: str = Field(min_length=1, max_length=120)
    price_usd: float | None = Field(default=None, gt=0, allow_inf_nan=False)


class AssetCheckoutRequest(BaseModel):
    customer_email: str = Field(min_length=3, max_length=254)
    item_id: str = Field(min_length=1, max_length=64)


class LicenseLookupRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)


class LicenseLookupVerifyRequest(LicenseLookupRequest):
    verification_code: str = Field(min_length=20, max_length=128)


class AssetRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(min_length=1, max_length=2000)
    category: str = Field(min_length=1, max_length=80)
    owner_email: str = Field(min_length=3, max_length=254)
    price_usd: float | None = Field(default=None, ge=0)


class AssetBuildRequest(BaseModel):
    tool_concept: str = Field(min_length=1, max_length=500)
    target_tier: Literal["Standard", "Enterprise", "Collector"] = "Standard"


class TradeOfferRequest(BaseModel):
    offering_owner_email: str = Field(min_length=3, max_length=254)
    offering_asset_id: str = Field(min_length=1, max_length=64)
    target_owner_email: str = Field(min_length=3, max_length=254)
    target_asset_id: str = Field(min_length=1, max_length=64)


def stripe_checkout_configured():
    return all(os.getenv(name) for name in (
        "STRIPE_WEBHOOK_SECRET",
        "STRIPE_SUCCESS_URL",
        "STRIPE_CANCEL_URL",
    )) and bool(STRIPE_SECRET_KEY)


def _send_email(to_email: str, subject: str, content: str) -> None:
    if not all((SMTP_HOST, SMTP_USER, SMTP_PASSWORD, SENDER_EMAIL)):
        raise RuntimeError("SMTP is not configured")
    try:
        port = int(SMTP_PORT)
    except ValueError as error:
        raise RuntimeError("SMTP_PORT must be an integer") from error
    if not 1 <= port <= 65535:
        raise RuntimeError("SMTP_PORT is outside the valid range")

    message = EmailMessage()
    message.set_content(content)
    message["Subject"] = subject
    message["From"] = SENDER_EMAIL
    message["To"] = to_email

    with smtplib.SMTP(SMTP_HOST, port, timeout=20) as server:
        server.starttls(context=ssl.create_default_context())
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.send_message(message)


def send_license_email(to_email: str, item_name: str, license_key: str) -> None:
    _send_email(
        to_email,
        f"Din CyberGuard licensnøgle til {item_name}",
        (
            "Mange tak for dit køb hos CyberGuard!\n\n"
            f"Produkt: {item_name}\n"
            f"Din unikke licensnøgle er: {license_key}\n\n"
            "Gem denne nøgle et sikkert sted.\n"
            "Med venlig hilsen,\nCyberGuard Teamet"
        ),
    )


def _normalized_email(email: str) -> str:
    normalized = email.strip().casefold()
    if "@" not in normalized or any(char.isspace() for char in normalized):
        raise HTTPException(status_code=422, detail="Indtast en gyldig e-mailadresse")
    return normalized


def require_settings_admin(
    credentials: HTTPBasicCredentials | None = Depends(settings_security),
) -> None:
    admin_password = os.getenv("STRIPE_SETTINGS_PASSWORD")
    if not admin_password:
        raise HTTPException(
            status_code=503,
            detail="Indstil STRIPE_SETTINGS_PASSWORD som en Codespaces Secret for at aktivere menuen",
        )
    if (
        credentials is None
        or credentials.username != "admin"
        or not hmac.compare_digest(credentials.password, admin_password)
    ):
        raise HTTPException(
            status_code=401,
            detail="Administratoradgang kræves",
            headers={"WWW-Authenticate": "Basic"},
        )


def settings_page(message: str = "") -> HTMLResponse:
    configured = bool(STRIPE_SECRET_KEY)
    status = "Stripe API-nøgle er indstillet." if configured else "Stripe API-nøgle mangler."
    content = f"""<!doctype html>
<html lang="da">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Stripe-indstillinger</title>
</head>
<body>
  <main>
    <h1>Stripe-indstillinger</h1>
    <p>{status}</p>
    <p>{message}</p>
    <form method="post" action="/settings">
      <label for="api_key">Stripe secret API key</label>
      <input id="api_key" name="api_key" type="password" autocomplete="new-password" required>
      <button type="submit">Gem nøgle</button>
    </form>
    <p>Nøglen gemmes kun i serverens hukommelse og skal indtastes igen efter genstart.</p>
  </main>
</body>
</html>"""
    return HTMLResponse(
        content,
        headers={
            "Cache-Control": "no-store",
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
            "Referrer-Policy": "no-referrer",
            "X-Content-Type-Options": "nosniff",
        },
    )

@app.get("/")
def root():
    return FileResponse(
        os.path.join(os.path.dirname(__file__), "index.html"),
        media_type="text/html",
    )


@app.get("/settings", response_class=HTMLResponse)
def stripe_settings_page(_: None = Depends(require_settings_admin)):
    return settings_page()


@app.post("/settings", response_class=HTMLResponse)
async def save_stripe_settings(
    request: Request,
    _: None = Depends(require_settings_admin),
):
    global STRIPE_SECRET_KEY

    origin = request.headers.get("origin")
    if not origin:
        raise HTTPException(status_code=403, detail="Origin-header mangler")
    parsed_origin = urlsplit(origin)
    if (
        parsed_origin.scheme != request.url.scheme
        or parsed_origin.netloc != request.url.netloc
    ):
        raise HTTPException(status_code=403, detail="Anmodningen kom fra en anden side")
    if request.headers.get("content-type", "").split(";", 1)[0].strip() != (
        "application/x-www-form-urlencoded"
    ):
        raise HTTPException(status_code=415, detail="Formularformatet understøttes ikke")

    try:
        form = parse_qs(
            (await request.body()).decode("utf-8"),
            keep_blank_values=True,
            strict_parsing=True,
            max_num_fields=2,
        )
    except (UnicodeDecodeError, ValueError) as error:
        raise HTTPException(status_code=400, detail="Ugyldig formular") from error

    submitted_keys = form.get("api_key", [])
    if len(submitted_keys) != 1:
        raise HTTPException(status_code=400, detail="Indtast én Stripe API-nøgle")
    api_key = submitted_keys[0].strip()
    if len(api_key) > 512 or not api_key.startswith(("sk_test_", "sk_live_", "rk_test_", "rk_live_")):
        raise HTTPException(status_code=400, detail="Indtast en Stripe secret API-nøgle")

    STRIPE_SECRET_KEY = api_key
    return settings_page("Nøglen er gemt i hukommelsen. Den vises ikke igen.")


@app.post("/api/cyber-drone/chat")
def cyber_drone_chat(message: ChatMessage):
    query = message.user_query.lower()
    if any(term in query for term in ("invest", "værdi", "sjælden", "rare")):
        reply = (
            "CyberGuard-investeringer er tænkt som køb af værktøjer eller sjældne bot-slots. "
            "Værdien kan ændre sig, men en stigning er ikke garanteret. Denne backend har "
            "endnu ikke prisdata, bot-slots eller et investeringsmarked."
        )
    elif any(term in query for term in ("trade", "trading", "bytte", "handl", "bot-slot", "botslot")):
        reply = (
            "CyberGuard planlægger et CS.Money-inspireret marked, hvor brugere kan bytte "
            "værktøjer, licenser og bot-slots. Direkte handler understøttes ikke endnu; "
            "denne installation har ikke et trade-endpoint."
        )
    elif any(term in query for term in ("asset", "værktøj", "builder", "byg", "skab", "opret")):
        reply = (
            "Custom Asset Builder kan registrere navn, beskrivelse, kategori og ejer for et "
            "værktøj via create-asset-endpointet. Assets kan ikke sættes til salg eller trade "
            "i denne installation, og indsendt kode bliver ikke kørt."
        )
    elif any(term in query for term in ("pris", "køb", "licens", "nøgle", "key")):
        reply = (
            "Licens-endpointet udsteder en unik nøgle i formatet CYBERGUARD-XXXX-XXXX og "
            "gemmer den i SQLite. Betalingsbehandling og prissætning er ikke konfigureret, "
            "så en udstedt nøgle bekræfter ikke en betaling."
        )
    elif any(term in query for term in ("scan", "skan", "trussel", "trusselskanning")):
        reply = (
            "Cyber Drone kan forklare trusselskanninger, men denne chatbot udfører ikke "
            "scanninger og har ikke adgang til systemets sikkerhedstilstand."
        )
    elif any(term in query for term in ("yknighter", "masterplan")):
        reply = (
            "YKnighter-masterplanen er ikke konfigureret i denne installation. "
            "Tilføj verificeret indhold, før chatbotten kan svare på dens detaljer."
        )
    else:
        reply = (
            "Jeg kan svare på dansk om CyberGuard-trading, investeringer, Custom Asset Builder, "
            "licensnøgler og trusselskanninger. Jeg bruger ingen ekstern AI-tjeneste."
        )
    return {"agent": "Cyber Drone v2.0", "response": reply}


@app.post("/api/cyber-drone/build-assistant")
def build_assistant(request: AssetBuildRequest):
    concept = request.tool_concept.casefold()
    is_standard = request.target_tier == "Standard"

    if "firewall" in concept or "filter" in concept:
        recommendation = (
            "Cyber Drone Builder: Overvej automatiske regelopdateringer og løbende logovervågning. "
            "Forslaget er ikke en sikkerhedstest eller godkendelse af værktøjet."
        )
        suggested_price = 450.00 if is_standard else 1500.00
    elif "bot" in concept or "scanner" in concept:
        recommendation = (
            "Cyber Drone Builder: Overvej at begrænse bot-slots for at styre kapaciteten. "
            "Begrænset antal garanterer ikke sjældenhed eller værdistigning."
        )
        suggested_price = 800.00 if is_standard else 2200.00
    else:
        recommendation = (
            f"Cyber Drone Builder: Konceptet '{request.tool_concept}' kan registreres til review. "
            "Forslaget er ikke en sikkerhedstest eller godkendelse af værktøjet."
        )
        suggested_price = 300.00

    return {
        "agent": "Cyber Drone Builder Assistant v3.0 (regelbaseret)",
        "analysis": recommendation,
        "suggested_price_usd": suggested_price,
        "status": "Recommendation ready",
        "disclaimer": "Prisforslaget er vejledende og ikke investeringsrådgivning.",
    }


@app.get("/api/market/items")
def get_market_items():
    checkout_enabled = stripe_checkout_configured()
    return {
        "currency": "USD",
        "purchase_enabled": checkout_enabled,
        "availability_note": (
            "Betaling behandles via Stripe Checkout."
            if checkout_enabled
            else "Katalogopslag; Stripe Checkout er ikke konfigureret."
        ),
        "featured_items": [
            {
                "id": "SEC-ENT-01",
                "name": "CyberGuard Enterprise Defense Suite",
                "price": 2500.00,
                "tier": "Enterprise (High-Value)",
                "type": "License & Bot-Slot Package",
                "availability": "available" if checkout_enabled else "catalog_only",
                "purchasable": checkout_enabled,
            },
            {
                "id": "SEC-BOT-X",
                "name": "Apex Security Bot Slot #001",
                "price": 1200.00,
                "tier": "Collector / Investment",
                "type": "Custom Asset Slot",
                "availability": "available" if checkout_enabled else "catalog_only",
                "purchasable": checkout_enabled,
            },
            {
                "id": "SEC-STD-05",
                "name": "Standard Shield License",
                "price": 150.00,
                "tier": "Standard",
                "type": "CYBERGUARD License",
                "availability": "available" if checkout_enabled else "catalog_only",
                "purchasable": checkout_enabled,
            },
            {
                "id": "TRADE-SWAP",
                "name": "Trade & Swap Listings",
                "price": None,
                "tier": "Trade & Swap Assets",
                "type": "Direct trade (no cash price)",
                "availability": "not_configured",
                "purchasable": False,
            },
        ],
    }


@app.get("/api/market/products")
def get_market_products(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    category: str | None = Query(default=None, min_length=1, max_length=80),
):
    query = (
        "SELECT id, name, price_usd, category, description FROM assets"
    )
    parameters: list[str | int] = []
    if category is not None:
        query += " WHERE category = ?"
        parameters.append(category)
    query += " ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?"
    parameters.extend((limit, offset))

    with sqlite3.connect(DB_FILE) as db:
        rows = db.execute(query, parameters).fetchall()

    checkout_enabled = stripe_checkout_configured()
    products = [
        {
            "item_id": row[0],
            "item_name": row[1],
            "price_usd": row[2],
            "category": row[3],
            "description": row[4],
            "purchasable": checkout_enabled and row[2] is not None
            and row[2] > 0 and round(row[2] * 100) >= 1,
        }
        for row in rows
    ]
    return {
        "limit": limit,
        "offset": offset,
        "total_returned": len(products),
        "products": products,
    }


@app.post("/api/market/purchase")
def complete_purchase(purchase: PurchaseRequest):
    raise HTTPException(
        status_code=409,
        detail="Licens udstedes først efter verificeret betaling via /api/market/checkout.",
    )


@app.post("/api/market/lookup/request", status_code=202)
def request_license_lookup(lookup: LicenseLookupRequest):
    customer_email = _normalized_email(lookup.email)
    verification_code = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(verification_code.encode("utf-8")).hexdigest()

    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("BEGIN IMMEDIATE")
        has_licenses = conn.execute(
            "SELECT 1 FROM orders WHERE customer_email = ? AND status = 'paid' LIMIT 1",
            (customer_email,),
        ).fetchone()
        if not has_licenses:
            return {
                "message": "Hvis e-mailen har købte licenser, sendes en bekræftelseskode.",
            }

        recent_request = conn.execute(
            "SELECT 1 FROM lookup_verifications "
            "WHERE customer_email = ? AND requested_at > datetime('now', '-1 minute')",
            (customer_email,),
        ).fetchone()
        if recent_request:
            return {
                "message": "Hvis e-mailen har købte licenser, sendes en bekræftelseskode.",
            }

        conn.execute(
            "INSERT INTO lookup_verifications "
            "(customer_email, token_hash, expires_at, requested_at, attempts) "
            "VALUES (?, ?, datetime('now', '+10 minutes'), CURRENT_TIMESTAMP, 0) "
            "ON CONFLICT(customer_email) DO UPDATE SET "
            "token_hash = excluded.token_hash, expires_at = excluded.expires_at, "
            "requested_at = excluded.requested_at, attempts = 0",
            (customer_email, token_hash),
        )

    try:
        _send_email(
            customer_email,
            "Din CyberGuard-bekræftelseskode",
            (
                "Brug denne kode for at se dine CyberGuard-licenser:\n\n"
                f"{verification_code}\n\n"
                "Koden udløber om 10 minutter og kan kun bruges én gang. "
                "Hvis du ikke har bedt om den, kan du ignorere denne e-mail."
            ),
        )
    except (RuntimeError, smtplib.SMTPException, OSError):
        logger.error("Could not send license lookup verification email")
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute(
                "DELETE FROM lookup_verifications "
                "WHERE customer_email = ? AND token_hash = ?",
                (customer_email, token_hash),
            )
        raise HTTPException(status_code=503, detail="Kunne ikke sende bekræftelsesmailen")

    return {"message": "Hvis e-mailen har købte licenser, sendes en bekræftelseskode."}


@app.post("/api/market/lookup")
def lookup_licenses(lookup: LicenseLookupVerifyRequest):
    customer_email = _normalized_email(lookup.email)
    supplied_hash = hashlib.sha256(lookup.verification_code.encode("utf-8")).hexdigest()

    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("BEGIN IMMEDIATE")
        verification = conn.execute(
            "SELECT token_hash, expires_at > CURRENT_TIMESTAMP, attempts "
            "FROM lookup_verifications "
            "WHERE customer_email = ?",
            (customer_email,),
        ).fetchone()
        invalid_code = verification is None or not verification[1]
        if invalid_code:
            conn.execute(
                "DELETE FROM lookup_verifications WHERE customer_email = ?",
                (customer_email,),
            )
        elif not secrets.compare_digest(verification[0], supplied_hash):
            attempts = verification[2] + 1
            if attempts >= 5:
                conn.execute(
                    "DELETE FROM lookup_verifications WHERE customer_email = ?",
                    (customer_email,),
                )
            else:
                conn.execute(
                    "UPDATE lookup_verifications SET attempts = ? WHERE customer_email = ?",
                    (attempts, customer_email),
                )
            invalid_code = True
        else:
            conn.execute(
                "DELETE FROM lookup_verifications WHERE customer_email = ?",
                (customer_email,),
            )
            rows = conn.execute(
                "SELECT o.item_name, o.price_usd, l.license_key, l.created_at "
                "FROM orders o JOIN licenses l ON l.order_id = o.id "
                "WHERE o.customer_email = ? AND o.status = 'paid' "
                "ORDER BY l.created_at DESC",
                (customer_email,),
            ).fetchall()

    if invalid_code:
        raise HTTPException(status_code=400, detail="Ugyldig eller udløbet bekræftelseskode")

    return {
        "email": customer_email,
        "licenses": [
            {
                "item_name": row[0],
                "price_usd": row[1],
                "license_key": row[2],
                "created_at": row[3],
            }
            for row in rows
        ],
    }


@app.post("/api/market/checkout", status_code=202)
def process_checkout(order: CheckoutRequest | AssetCheckoutRequest):
    if not stripe_checkout_configured():
        raise HTTPException(status_code=503, detail="Stripe Checkout er ikke konfigureret")

    customer_email = _normalized_email(order.customer_email)
    if isinstance(order, AssetCheckoutRequest):
        with sqlite3.connect(DB_FILE) as conn:
            asset = conn.execute(
                "SELECT id, name, price_usd FROM assets WHERE id = ?",
                (order.item_id,),
            ).fetchone()
        if asset is None or asset[2] is None or asset[2] <= 0:
            raise HTTPException(status_code=404, detail="Produktet findes ikke eller kan ikke købes")
        item_id, item_name, expected_price = asset[0], asset[1], round(float(asset[2]), 2)
    else:
        products = get_market_items()["featured_items"]
        product = next((item for item in products if item["name"] == order.item_name), None)
        if product is None or product["price"] is None or not product["purchasable"]:
            raise HTTPException(status_code=404, detail="Produktet findes ikke eller kan ikke købes")

        item_id = product["id"]
        item_name = product["name"]
        expected_price = float(product["price"])
        if order.price_usd is not None and round(order.price_usd, 2) != round(expected_price, 2):
            raise HTTPException(status_code=409, detail="Prisen stemmer ikke med serverens katalog")

    unit_amount = int(round(expected_price * 100))
    if unit_amount < 1:
        raise HTTPException(status_code=409, detail="Produktets pris er for lav til Stripe Checkout")

    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.execute(
            "INSERT INTO orders (customer_email, item_id, item_name, price_usd, status) "
            "VALUES (?, ?, ?, ?, 'pending_payment')",
            (
                customer_email,
                item_id,
                item_name,
                expected_price,
            )
        )
        order_id = cursor.lastrowid

    stripe.api_key = STRIPE_SECRET_KEY
    try:
        session = stripe.checkout.Session.create(
            mode="payment",
            payment_method_types=["card"],
            customer_email=customer_email,
            success_url=os.environ["STRIPE_SUCCESS_URL"],
            cancel_url=os.environ["STRIPE_CANCEL_URL"],
            line_items=[{
                "price_data": {
                    "currency": "usd",
                    "product_data": {"name": item_name},
                    "unit_amount": unit_amount,
                },
                "quantity": 1,
            }],
            metadata={"order_id": str(order_id), "item_id": item_id},
        )
    except stripe.StripeError as error:
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute("UPDATE orders SET status = 'checkout_failed' WHERE id = ?", (order_id,))
        raise HTTPException(status_code=502, detail="Stripe kunne ikke oprette checkout-sessionen") from error

    with sqlite3.connect(DB_FILE) as conn:
        conn.execute(
            "UPDATE orders SET stripe_session_id = ?, checkout_url = ? WHERE id = ?",
            (session.id, session.url, order_id)
        )

    return {
        "status": "pending_payment",
        "order_id": order_id,
        "item": item_name,
        "price_usd": expected_price,
        "license_key": None,
        "checkout_url": session.url,
        "message": "Checkout-session oprettet. Licens udstedes først efter verificeret betaling.",
    }


@app.post("/api/webhook/stripe")
async def stripe_webhook(request: Request):
    webhook_secret = os.getenv("STRIPE_WEBHOOK_SECRET")
    if not webhook_secret:
        raise HTTPException(status_code=503, detail="Stripe webhook er ikke konfigureret")

    signature = request.headers.get("stripe-signature")
    if not signature:
        raise HTTPException(status_code=400, detail="Stripe-Signature header mangler")

    payload = await request.body()
    try:
        event = stripe.Webhook.construct_event(payload, signature, webhook_secret)
    except (ValueError, stripe.SignatureVerificationError) as error:
        raise HTTPException(status_code=400, detail="Ugyldig Stripe webhook-signatur") from error

    if event.get("type") != "checkout.session.completed":
        return {"received": True, "processed": False}

    session = event.get("data", {}).get("object", {})
    if session.get("payment_status") != "paid":
        return {"received": True, "processed": False, "reason": "payment_not_paid"}

    metadata = session.get("metadata") or {}
    try:
        order_id = int(metadata.get("order_id", ""))
    except (TypeError, ValueError):
        return {"received": True, "processed": False, "reason": "order_id_missing"}

    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("BEGIN IMMEDIATE")
        order_row = conn.execute(
            "SELECT customer_email, item_name, status, stripe_session_id, license_key, email_sent "
            "FROM orders WHERE id = ?",
            (order_id,)
        ).fetchone()
        if order_row is None or order_row[3] != session.get("id"):
            return {"received": True, "processed": False, "reason": "order_not_found"}
        customer_email, item_name = order_row[0], order_row[1]
        license_key = order_row[4]
        if order_row[2] != "paid":
            for _ in range(5):
                license_key = f"CYBERGUARD-{secrets.token_hex(4).upper()}"
                try:
                    conn.execute(
                        "INSERT INTO licenses "
                        "(license_key, customer_email, asset_name, order_id) VALUES (?, ?, ?, ?)",
                        (license_key, customer_email, item_name, order_id)
                    )
                    break
                except sqlite3.IntegrityError:
                    continue
            else:
                raise HTTPException(status_code=500, detail="Kunne ikke generere en unik licensnøgle")

            conn.execute(
                "UPDATE orders SET status = 'paid', license_key = ?, payment_reference = ? WHERE id = ?",
                (license_key, session.get("payment_intent"), order_id)
            )
        email_sent = bool(order_row[5])

    if not license_key:
        raise HTTPException(status_code=500, detail="Ordren mangler en licensnøgle")

    if not email_sent:
        try:
            send_license_email(customer_email, item_name, license_key)
        except (RuntimeError, smtplib.SMTPException, OSError):
            logger.error("Could not send paid order license email for order %s", order_id)
            raise HTTPException(status_code=503, detail="Betalingen er registreret, men kvitteringsmailen kunne ikke sendes")
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute("UPDATE orders SET email_sent = 1 WHERE id = ?", (order_id,))

    return {"received": True, "processed": True}


@app.post("/api/market/create-asset", status_code=201)
def create_asset(asset: AssetRequest):
    asset_id = str(uuid.uuid4())
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute(
                "INSERT INTO assets (id, name, description, category, owner_email, price_usd) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    asset_id,
                    asset.name,
                    asset.description,
                    asset.category,
                    asset.owner_email.strip().casefold(),
                    asset.price_usd,
                )
            )
            conn.execute(
                "INSERT INTO inventory (owner_email, asset_id, acquired_via) "
                "VALUES (?, ?, 'custom_asset')",
                (asset.owner_email.strip().casefold(), asset_id)
            )
    except sqlite3.Error as error:
        raise HTTPException(status_code=500, detail="Kunne ikke gemme asset") from error

    return {"status": "Success", "asset_id": asset_id, "asset": asset.model_dump()}


@app.post("/api/market/trade/offer", status_code=201)
def create_trade_offer(trade: TradeOfferRequest):
    offering_owner = trade.offering_owner_email.strip().casefold()
    target_owner = trade.target_owner_email.strip().casefold()
    if offering_owner == target_owner:
        raise HTTPException(status_code=400, detail="Bytteforslaget skal have to forskellige ejere")

    try:
        with sqlite3.connect(DB_FILE) as conn:
            offering_asset = conn.execute(
                "SELECT 1 FROM inventory WHERE owner_email = ? AND asset_id = ?",
                (offering_owner, trade.offering_asset_id)
            ).fetchone()
            if offering_asset is None:
                raise HTTPException(status_code=404, detail="Det tilbudte asset findes ikke i ejerens inventory")

            target_asset = conn.execute(
                "SELECT 1 FROM inventory WHERE owner_email = ? AND asset_id = ?",
                (target_owner, trade.target_asset_id)
            ).fetchone()
            if target_asset is None:
                raise HTTPException(status_code=404, detail="Det ønskede asset findes ikke i modtagerens inventory")

            cursor = conn.execute(
                "INSERT INTO trades (from_email, from_asset_id, to_email, to_asset_id) "
                "VALUES (?, ?, ?, ?)",
                (offering_owner, trade.offering_asset_id, target_owner, trade.target_asset_id)
            )
            trade_id = cursor.lastrowid
    except sqlite3.Error as error:
        raise HTTPException(status_code=500, detail="Kunne ikke oprette bytteforslaget") from error

    return {
        "status": "success",
        "trade_id": trade_id,
        "trade_status": "pending",
        "message": "Bytteforslag oprettet. Ingen assets er overført endnu.",
    }