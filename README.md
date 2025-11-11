# WeakPoint Website Check

Een modernere opzet voor de oorspronkelijke scanner: een Python-backend (FastAPI) levert de beveiligingsscan als JSON, terwijl een React-frontend gebruikers een nette UI geeft om hun URL te laten controleren. De scanner combineert passieve checks met een optionele, lichte **pentest**-module (geen bruteforce of destructieve requests) en groepeert bevindingen in **kritische**, **belangrijke**, **pentest** en **nice-to-have** categorieën.

```
Weakpoint-website-check/
├─ backend/
│  ├─ app.py            # FastAPI API + CORS
│  ├─ scanner.py        # Kernscanner (CLI én API reuse)
│  ├─ requirements.txt  # Backend dependencies
│  └─ Dockerfile
├─ frontend/
│  ├─ src/              # React UI
│  ├─ Dockerfile
│  └─ nginx.conf        # Proxy /api naar backend service
├─ docker-compose.yml
└─ README.md
```

## Functionaliteiten

| Categorie | Checks (samenvatting) |
| --- | --- |
| Kritisch | TLS/HTTPS (keten, verlopen, legacy protocollen), security headers (CSP/HSTS/XFO/etc.), mixed content, redirect/canonical hygiëne, CORS-configuratie, cookies (Secure/HttpOnly/SameSite), forms/input validatie. |
| Belangrijk | Inline XSS hints, SQL/command error leakage, authenticatie & sessiebeheer (POST, CSRF, rate limiting, MFA-verwijzing), server banners / verouderde software, publieke backup/config files, rate-limit inzicht, error handling (verbose errors). |
| Pentest | Actieve formulierinjecties (XSS reflectie, SQL-foutdetectie, WAF-reacties) met veilige payloads. |
| Nice-to-have | Performance/TTFB + grootte, basis toegankelijkheid, SEO-meta & sitemap, mobile/viewport, third-party scripts, privacy/cookieverwijzingen. |

Alle check-resultaten bevatten een korte samenvatting, impact/status (`pass`, `warn`, `fail`, `info`), remediation-tip en optionele detailpayload (JSON) die de UI kan tonen.

## Vereisten

- Python 3.9+
- Node.js 18+ / npm 9+

## Backend (FastAPI) gebruiken

```powershell
cd backend
python -m venv .venv
.venv\Scripts\activate      # macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
uvicorn backend.app:app --reload --port 8000
```

### CLI fallback
Je kunt de scanner ook rechtstreeks draaien zonder de API:

```powershell
python -m backend.scanner --url https://example.com --output report.json --max-pages 120
```

Gebruik `--max-pages` om tijdelijk een andere limiet af te dwingen; laat de vlag weg om de standaard (50 pagina's per scan) aan te houden.

### API endpoints

| Methode | Pad | Body | Beschrijving |
| --- | --- | --- | --- |
| `GET` | `/healthz` | – | Gezondheidscheck (handig voor k8s/compose). |
| `POST` | `/api/scan` | `{ "url": "https://voorbeeld.nl", "max_pages": 120 }` (optioneel) | Draait alle checks en retourneert het rapport (`meta`, `critical`, `important`, `pentest`, `nice_to_have`). |
| `GET` | `/api/scan/stream` | Query: `?url=https://voorbeeld.nl&max_pages=120` | Server-Sent Events stream voor live voortgang inclusief gescande pagina's en het eindrapport. |

### Pagina-limieten en defaults

- De frontend bevat een schuif (20-500 pagina's) met standaardwaarde 50 zodat grote sites direct resultaat geven zonder dat de crawler vastloopt.
- Zowel de API-body als de stream-endpoint accepteren `max_pages`; laat de parameter weg om de standaard 50 pagina's te gebruiken.
- `WEAKPOINT_MAX_PAGES` is het harde backend-maximum (default 500). Zet je deze lager, dan clampen API en UI de waarde automatisch.
- Het aantal seed-URL's en sitemap-entries schaalt mee met je gekozen budget. Wil je het absoluut begrenzen, gebruik dan `WEAKPOINT_MAX_SEED_URLS` en/of `WEAKPOINT_MAX_SITEMAP_URLS`.
- De ingestelde limiet is een bovengrens: als een scan minder pagina's oplevert betekent dat dat er minder unieke HTML-pagina's bereikbaar zijn via statische links, robots.txt of sitemaps (denk aan JS-routes of logins).

Voorbeeld responsefragment:

```json
{
  "meta": {
    "target": "https://example.com",
    "final_url": "https://www.example.com/",
    "status_code": 200,
    "timestamp": "2025-11-08T20:35:12.821394+00:00"
  },
  "critical": [
    {
      "id": "tls",
      "title": "HTTPS / TLS",
      "status": "pass",
      "summary": "Geldig certificaat en moderne TLS-configuratie aangetroffen.",
      "remediation": "Blijf certificaten automatisch vernieuwen en schakel zwakke ciphers uit.",
      "details": { "tls_version": "TLSv1.3", "days_remaining": 62 }
    }
  ],
  "pentest": [
    {
      "id": "active_forms",
      "title": "Actieve formulier pentest",
      "status": "pass",
      "summary": "Formulieren filteren actieve payloads of reageren veilig.",
      "details": { "tested_forms": 3 }
    }
  ]
}
```

## Pentest-module (actieve checks)

- Test maximaal 8 formulieren met een veilige payload (`"'&lt;weakpoint-…`) om XSS-reflectie of SQL-foutmeldingen uit te lokken.
- Rapporteert ongesanitized reflecties als **fail**, geblokkeerde requests als **warn** en geslaagde filtering als **pass**.
- Produceert geen brute-force verkeer en gebruikt standaard timeouts/headers van de passieve scanner.
- De payload en doel-URL's van de actieve requests worden in de `details`-sectie gelogd zodat je het gedrag kunt reproduceren.

### Headless fallback (optioneel)

Sommige sites blokkeren standaard HTTP-clients met JavaScript- of WAF-checks. Voor je **eigen** domeinen kun je een headless browser laten meedraaien zodat de scanner dezelfde pagina HTML ontvangt als een echte bezoeker:

1. Installeer Playwright en de Chromium-driver:
   ```powershell
   pip install playwright
   playwright install chromium
   ```
2. Zet vóór het starten van de backend de env-var aan: `WEAKPOINT_HEADLESS=1`.

Wanneer een request een blokkerende status (403/429/...) teruggeeft, probeert de scanner opnieuw via Playwright. Gebruik dit alleen intern of met toestemming; het omzeilt client-side checks.

Met `docker compose` gebeurt dit automatisch: het backend-image installeert Playwright/Chromium tijdens de build en de service draait standaard met `WEAKPOINT_HEADLESS=1`.

## Frontend (React) gebruiken

```powershell
cd frontend
npm install
npm run dev             # start Vite op http://localhost:5173 (proxy naar http://localhost:8000)
```


- In development proxyt Vite automatisch `/api` en `/healthz` naar `http://localhost:8000`.
- Voor productie kun je `VITE_API_URL=https://scanner.mijnbedrijf.nl` zetten en `npm run build` draaien. De gegenereerde assets staan in `frontend/dist`.

## Docker workflow

Geheel draaien zonder Node/Python lokaal te installeren:

```powershell
docker compose up --build
```

- Backend draait op `http://localhost:8000`
- Frontend wordt door nginx geserveerd op `http://localhost:4173` en proxyt `/api` naar de backend service

Gebruik `docker compose down` om de stack te stoppen. Pas indien nodig de poorten aan in `docker-compose.yml`.

## Samenbrengen (lokale workflow)

1. Start de backend: `uvicorn backend.app:app --reload --port 8000`
2. Start de frontend: `npm run dev` (Vite) – open daarna `http://localhost:4173`
3. Plak een URL in de UI en druk op **Start scan**. Resultaten worden onderverdeeld per categorie en opgeslagen in de korte geschiedenis onder het formulier.

## Ethische richtlijnen

- Scan alleen doelen waarvoor je expliciete toestemming hebt.
- De tool doet geen brute-force, maar sommige checks (bv. backup-bestanden en de actieve formulierprobe) sturen extra requests. Gebruik lage frequentie en respecteer robots/ToS.
- Voor diepgaande pentests blijft inzet van gespecialiseerde tooling (OWASP ZAP, Burp, Nessus, …) en professioneel personeel noodzakelijk; deze pentest-module is beperkt tot veilige probe-requests.

## Verdere ideeën

- Async queue + worker zodat scans niet de API-thread blokkeren.
- Opslaan van historische rapporten (PostgreSQL) en diffing tussen scans.
- Integratie met Lighthouse/axe-core voor uitgebreidere performance & accessibility insights.
- Authenticatie voor de frontend zodat klanten hun eigen scans kunnen beheren.
