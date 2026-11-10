# CyberGuard API

## Deploy to Render

The repository includes a Render Blueprint in `render.yaml`. It deploys the FastAPI app and marketplace page together, serves the page at `/`, and attaches a 1 GB persistent disk at `/var/data` for SQLite orders, licenses, and assets. The Blueprint selects Render's `starter` plan because persistent disks require a paid service; check Render's current pricing before deploying.

In Render, create a Blueprint from this GitHub repository and review the service and disk costs before confirming. Set the prompted environment variables in the Render dashboard:

- `STRIPE_SECRET_KEY`: a rotated Stripe secret API key.
- `STRIPE_WEBHOOK_SECRET`: the webhook signing secret.
- `STRIPE_SUCCESS_URL` and `STRIPE_CANCEL_URL`: HTTPS URLs on the deployed `onrender.com` domain.
- `STRIPE_SETTINGS_PASSWORD`: a strong, separate admin password.
- `SMTP_HOST`, `SMTP_USER`, `SMTP_PASSWORD`, `SENDER_EMAIL`: SMTP credentials for receipts and lookup codes. `SMTP_PORT` defaults to `587`.

The environment variables are not stored in this repository. Do not put secret values in `render.yaml`, GitHub, or chat. After the first deploy, use the actual Render domain to set the Stripe success/cancel URLs and create a Stripe webhook destination at `https://YOUR-RENDER-DOMAIN/api/webhook/stripe` for `checkout.session.completed`. The `DB_FILE` variable in the Blueprint points SQLite to the persistent disk; keep it there so redeploys do not lose orders or licenses.

A fresh Render disk starts with an empty product catalog; the local `cyberguard.db` is not deployed. The generated products from `seed_products.py` are explicitly test data and should not be loaded into a live store with Stripe enabled. Add and verify real catalog entries before accepting live payments.

## Stripe test setup

For Codespaces, add these as Codespaces secrets; do not commit Stripe keys:

- `STRIPE_WEBHOOK_SECRET`: webhook signing secret (`whsec_...`).
- `STRIPE_SUCCESS_URL`: HTTPS URL for the post-checkout success page; include `{CHECKOUT_SESSION_ID}` if the page needs to look up the session.
- `STRIPE_CANCEL_URL`: HTTPS URL for the cancelled-checkout page.
- `STRIPE_SETTINGS_PASSWORD`: a strong, separate password for the protected settings page.
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SENDER_EMAIL`: SMTP server settings for license receipts and lookup verification emails. Keep the password in Codespaces secrets.

In Stripe Workbench, create a webhook destination for `https://YOUR-CODESPACE-8000.app.github.dev/api/webhook/stripe` and subscribe to `checkout.session.completed`. Copy its signing secret to `STRIPE_WEBHOOK_SECRET`, then restart the API so it reads the new secrets.

Open `https://YOUR-CODESPACE-8000.app.github.dev/settings` and sign in with username `admin` and the `STRIPE_SETTINGS_PASSWORD` value. Enter your Stripe secret API key there. The key stays in server memory only and must be entered again after an API restart; use Codespaces secrets for persistent configuration instead. Never share Stripe keys in chat or commit them to the repository.

The API uses server-side catalog or asset prices, creates orders with `pending_payment` status, and returns a Stripe Checkout URL. Asset checkout accepts `{"item_id":"BOT-PROD-0001","customer_email":"customer@example.com"}` at `POST /api/market/checkout`; the customer email and item ID are required. The server never trusts a price from the browser. It changes an order to `paid` and issues a license only after receiving a valid signed event whose payment status is `paid`. The old `/api/market/purchase` route is disabled to prevent issuing licenses without a verified payment.

After payment, the webhook sends a license receipt through SMTP. If SMTP delivery fails, the webhook returns an error so Stripe can retry; the order and license remain recorded, and retries do not issue another license.

To look up licenses, first send `POST /api/market/lookup/request` with `{"email":"customer@example.com"}`. The customer receives a one-time verification code by email. Submit it to `POST /api/market/lookup` with `{"email":"customer@example.com","verification_code":"..."}`. Codes expire after 10 minutes, can be used once, and allow at most five attempts. The request response does not reveal whether the email has purchased licenses.

Custom assets are available from the paginated `GET /api/market/products` endpoint. It reads from the existing `assets` table; use `limit` (1–100, default 50), `offset` (default 0), and optional exact-match `category` query parameters. For example: `/api/market/products?limit=50&offset=0&category=Security`.

To add 1,000 synthetic example assets for testing, run `.venv/bin/python seed_products.py` (or `python seed_products.py`). The script inserts test data without replacing existing assets; rerunning it is safe.

The marketplace page is served at `/` and loads 20 products at a time from `/api/market/products`. Customers enter an email to receive the receipt and license. Purchase buttons are enabled only for products with a positive price when Stripe Checkout is configured.
