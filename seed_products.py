import random
import sqlite3
import sys

DB_FILE = "cyberguard.db"

categories = ["Security", "Bot", "Exploit", "Defense", "Network", "AI-Core"]
adjectives = [
    "Advanced",
    "Neural",
    "Secure",
    "Cyber",
    "Autonomous",
    "Quantum",
    "Elite",
    "Stealth",
]
nouns = [
    "Firewall",
    "Shield",
    "Scanner",
    "Botnet",
    "Proxy",
    "Analyzer",
    "Decoder",
    "Tracker",
]


def generate_test_products(total: int = 1000) -> None:
    if total < 1:
        raise ValueError("total must be greater than zero")

    products = []
    for index in range(1, total + 1):
        item_id = f"BOT-PROD-{index:04d}"
        name = (
            f"{random.choice(adjectives)} {random.choice(nouns)} "
            f"v{random.randint(1, 5)}.{random.randint(0, 9)}"
        )
        description = (
            f"Automatisk genereret test-asset nr. {index}; "
            "produktet er eksempeldata og udfører ingen sikkerhedsfunktioner."
        )
        category = random.choice(categories)
        owner_email = f"bot-creator-{random.randint(1, 50)}@cyberguard.local"
        price_usd = round(random.uniform(5.0, 199.99), 2)
        products.append(
            (item_id, name, description, category, owner_email, price_usd)
        )

    print(f"Genererer op til {total} test-produkter i {DB_FILE}...")
    with sqlite3.connect(DB_FILE) as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS assets (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT NOT NULL,
                category TEXT NOT NULL,
                owner_email TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        columns = {row[1] for row in db.execute("PRAGMA table_info(assets)")}
        if "price_usd" not in columns:
            db.execute("ALTER TABLE assets ADD COLUMN price_usd REAL")

        before = db.total_changes
        db.executemany(
            """
            INSERT OR IGNORE INTO assets
                (id, name, description, category, owner_email, price_usd)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            products,
        )
        inserted = db.total_changes - before
        total_assets = db.execute("SELECT COUNT(*) FROM assets").fetchone()[0]

    print(f"Indsat: {inserted}; eksisterende produkt-id'er blev ikke overskrevet.")
    print(f"Produkter i alt i assets-tabellen: {total_assets}.")


if __name__ == "__main__":
    try:
        requested_total = int(sys.argv[1]) if len(sys.argv) > 1 else 1000
        generate_test_products(requested_total)
    except ValueError as error:
        raise SystemExit(f"Ugyldigt antal produkter: {error}") from error
