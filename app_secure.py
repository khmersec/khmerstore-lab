"""
Khmer Store — Web Security Lab (SECURE VERSION)

This application demonstrates how to fix common web security vulnerabilities:
1. Server-side verification validation
2. Server-side authorization checks
3. Server-side role validation
4. Safe input handling

Run: python app_secure.py
Access: http://mystore.khmersec.com
"""

from flask import Flask, request, jsonify, session, render_template, redirect, url_for
from functools import wraps
import re
import os
import socket
import secrets
from datetime import datetime
from database import (
    init_db, get_db, hash_password, get_user_by_username, get_user_by_id,
    create_user, update_user_verified, update_user_name, update_user_role,
    update_user_profile, get_all_users, get_all_products, get_product_by_id,
    get_orders, get_user_orders, create_order, get_stats
)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# Secure session settings
app.config['SESSION_COOKIE_SECURE'] = True  # Only send over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # No JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'  # Strict CSRF protection

# Initialize database on startup
init_db()

# Request log
REQUEST_LOG = []


@app.after_request
def add_security_headers(response):
    """Add security headers to responses."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
    return response


def get_local_ip():
    """Get the local IP address for network access."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def log_request(method, path, status_code, details=""):
    """Log all requests."""
    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "method": method,
        "path": path,
        "status_code": status_code,
        "details": details
    }
    REQUEST_LOG.append(entry)
    print(f"[{entry['timestamp']}] {method} {path} -> {status_code} {details}")


def login_required(f):
    """Decorator to require login."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            if request.is_json:
                return jsonify({"error": "Login required"}), 401
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Decorator to require admin role."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            if request.is_json:
                return jsonify({"error": "Login required"}), 401
            return redirect(url_for("login_page"))
        user = get_user_by_id(session["user_id"])
        if not user or user["role"] != "admin":
            if request.is_json:
                return jsonify({"error": "Admin access required"}), 403
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated_function


def sanitize_input(value):
    """Sanitize user input."""
    if not value:
        return value
    # Remove any HTML tags
    value = re.sub(r'<[^>]+>', '', value)
    # Remove any script tags
    value = re.sub(r'<script[^>]*>.*?</script>', '', value, flags=re.DOTALL)
    return value.strip()


# ============================================================
# Page Routes
# ============================================================

@app.route("/")
def index():
    """Home page."""
    products = get_all_products()[:8]
    return render_template("index.html", products=products)


@app.route("/products")
def products_page():
    """Products page."""
    products = get_all_products()
    return render_template("products.html", products=products)


@app.route("/register")
def register_page():
    """Register page."""
    return render_template("register.html")


@app.route("/login")
def login_page():
    """Login page."""
    return render_template("login.html")


@app.route("/verify")
def verify_page():
    """Verify page."""
    return render_template("verify.html")


@app.route("/account")
@login_required
def account_page():
    """Account page."""
    user = get_user_by_id(session["user_id"])
    return render_template("account.html", user=user)


@app.route("/profile")
@login_required
def profile_page():
    """Profile page."""
    user = get_user_by_id(session["user_id"])
    return render_template("profile.html", user=user)


@app.route("/admin")
@admin_required
def admin_page():
    """Admin dashboard."""
    return render_template("admin.html")


# ============================================================
# API Routes - Auth
# ============================================================

@app.route("/api/register", methods=["POST"])
def api_register():
    """Register new user."""
    data = request.get_json()

    if not data:
        return jsonify({"error": "No data provided"}), 400

    username = sanitize_input(data.get("username", ""))
    email = sanitize_input(data.get("email", ""))
    password = data.get("password", "")
    name = sanitize_input(data.get("name", ""))

    if not username or not email or not password:
        return jsonify({"error": "Missing required fields"}), 400

    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400

    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return jsonify({"error": "Username can only contain letters, numbers, and underscores"}), 400

    if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
        return jsonify({"error": "Invalid email format"}), 400

    result = create_user(username, email, password, name)

    if result:
        log_request("POST", "/api/register", 201, f"User {username} registered")
        return jsonify({
            "message": "User registered",
            "user_id": result["id"]
        }), 201
    else:
        log_request("POST", "/api/register", 400, "Username or email exists")
        return jsonify({"error": "Username or email already exists"}), 400


@app.route("/api/verify", methods=["POST"])
def api_verify():
    """
    Verify user account.
    SECURE: Server-side code validation.
    """
    data = request.get_json()

    if not data:
        return jsonify({"error": "No data provided"}), 400

    username = sanitize_input(data.get("username", ""))
    code = data.get("code", "")

    if not username or not code:
        return jsonify({"error": "Missing username or code"}), 400

    user = get_user_by_username(username)
    if not user:
        log_request("POST", "/api/verify", 404, "User not found")
        return jsonify({"error": "User not found"}), 404

    # SECURE: Server-side verification code validation
    if user["verification_code"] != code:
        log_request("POST", "/api/verify", 400, "Invalid verification code")
        return jsonify({"error": "Invalid verification code"}), 400

    update_user_verified(username)
    log_request("POST", "/api/verify", 200, f"User {username} verified")
    return jsonify({"message": "Account verified"}), 200


@app.route("/api/login", methods=["POST"])
def api_login():
    """Login user."""
    data = request.get_json()

    if not data:
        return jsonify({"error": "No data provided"}), 400

    username = sanitize_input(data.get("username", ""))
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400

    user = get_user_by_username(username)
    if not user:
        log_request("POST", "/api/login", 401, "Invalid credentials")
        return jsonify({"error": "Invalid credentials"}), 401

    if user["password_hash"] != hash_password(password):
        log_request("POST", "/api/login", 401, "Invalid credentials")
        return jsonify({"error": "Invalid credentials"}), 401

    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["role"] = user["role"]

    log_request("POST", "/api/login", 200, f"User {username} logged in")
    return jsonify({
        "message": "Login successful",
        "user": {
            "id": user["id"],
            "username": user["username"],
            "name": user["name"],
            "role": user["role"]
        }
    }), 200


@app.route("/api/logout", methods=["POST"])
def api_logout():
    """Logout user."""
    session.clear()
    log_request("POST", "/api/logout", 200)
    return jsonify({"message": "Logged out"}), 200


# ============================================================
# API Routes - Profile
# ============================================================

@app.route("/api/profile", methods=["GET"])
@login_required
def get_profile():
    """Get current user profile."""
    user = get_user_by_id(session["user_id"])
    log_request("GET", "/api/profile", 200)
    return jsonify({
        "id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "name": user["name"],
        "role": user["role"],
        "verified": bool(user["verified"]),
        "created_at": user["created_at"]
    })


@app.route("/api/profile/name", methods=["POST"])
@login_required
def update_name():
    """
    Update profile name.
    SECURE: No expression evaluation.
    """
    data = request.get_json()

    if not data:
        return jsonify({"error": "No data provided"}), 400

    name = sanitize_input(data.get("name", ""))
    if not name:
        return jsonify({"error": "Name is required"}), 400

    # SECURE: Store name as-is, no evaluation
    update_user_name(session["user_id"], name)
    log_request("POST", "/api/profile/name", 200, f"Name updated to: {name}")

    return jsonify({
        "message": "Name updated",
        "name": name
    }), 200


@app.route("/api/account/update", methods=["POST"])
@login_required
def update_account():
    """
    Update account settings.
    SECURE: Server-side role validation.
    """
    data = request.get_json()

    if not data:
        return jsonify({"error": "No data provided"}), 400

    name = sanitize_input(data.get("name", ""))
    role = data.get("role", "")

    # SECURE: Ignore role from client, only allow name update
    if role and role != session.get("role"):
        log_request("POST", "/api/account/update", 403, "Role modification denied")
        return jsonify({"error": "Cannot modify role"}), 403

    update_user_profile(session["user_id"], name=name)
    log_request("POST", "/api/account/update", 200, "Account updated")

    return jsonify({"message": "Account updated"}), 200


@app.route("/api/users/<int:user_id>", methods=["GET"])
@login_required
def get_user_by_id_endpoint(user_id):
    """
    Get user by ID.
    SECURE: Server-side authorization check.
    """
    # SECURE: Check if user is requesting their own profile or is admin
    current_user = get_user_by_id(session["user_id"])
    if session["user_id"] != user_id and current_user["role"] != "admin":
        log_request("GET", f"/api/users/{user_id}", 403, "Access denied")
        return jsonify({"error": "Access denied"}), 403

    user = get_user_by_id(user_id)
    if not user:
        log_request("GET", f"/api/users/{user_id}", 404, "User not found")
        return jsonify({"error": "User not found"}), 404

    log_request("GET", f"/api/users/{user_id}", 200, f"User {user_id} retrieved")
    return jsonify({
        "id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "name": user["name"],
        "role": user["role"],
        "verified": bool(user["verified"]),
        "created_at": user["created_at"]
    })


# ============================================================
# API Routes - Products
# ============================================================

@app.route("/api/products", methods=["GET"])
def get_products():
    """Get all products."""
    products = get_all_products()
    log_request("GET", "/api/products", 200)
    return jsonify({"products": products})


@app.route("/api/products/<int:product_id>", methods=["GET"])
def get_product(product_id):
    """Get product by ID."""
    product = get_product_by_id(product_id)
    if not product:
        log_request("GET", f"/api/products/{product_id}", 404)
        return jsonify({"error": "Product not found"}), 404

    log_request("GET", f"/api/products/{product_id}", 200)
    return jsonify(product)


# ============================================================
# API Routes - Orders
# ============================================================

@app.route("/api/orders", methods=["POST"])
@login_required
def create_order_endpoint():
    """Create new order."""
    data = request.get_json()

    if not data:
        return jsonify({"error": "No data provided"}), 400

    product_id = data.get("product_id")
    quantity = data.get("quantity", 1)

    if not product_id:
        return jsonify({"error": "Product ID required"}), 400

    product = get_product_by_id(product_id)
    if not product:
        return jsonify({"error": "Product not found"}), 404

    if product["stock"] < quantity:
        return jsonify({"error": "Insufficient stock"}), 400

    total = product["price"] * quantity
    order_id = create_order(session["user_id"], product_id, quantity, total)

    log_request("POST", "/api/orders", 201, f"Order {order_id} created")
    return jsonify({"message": "Order created", "order_id": order_id}), 201


@app.route("/api/orders", methods=["GET"])
@login_required
def get_orders_endpoint():
    """Get user orders."""
    orders = get_user_orders(session["user_id"])
    log_request("GET", "/api/orders", 200)
    return jsonify({"orders": orders})


# ============================================================
# API Routes - Admin
# ============================================================

@app.route("/api/admin/stats", methods=["GET"])
@admin_required
def get_stats_endpoint():
    """Get admin statistics."""
    stats = get_stats()
    log_request("GET", "/api/admin/stats", 200)
    return jsonify(stats)


@app.route("/api/admin/users", methods=["GET"])
@admin_required
def get_users():
    """Get all users."""
    users = get_all_users()
    log_request("GET", "/api/admin/users", 200)
    return jsonify({"users": users})


# ============================================================
# API Routes - Logs (Admin only)
# ============================================================

@app.route("/api/logs", methods=["GET"])
@admin_required
def get_logs():
    """Return request logs - ADMIN ONLY."""
    log_request("GET", "/api/logs", 200)
    return jsonify({
        "logs": REQUEST_LOG[-50:],
        "total": len(REQUEST_LOG)
    })


# ============================================================
# Health Check
# ============================================================

@app.route("/health")
def health():
    """Health check endpoint."""
    log_request("GET", "/health", 200)
    return jsonify({
        "status": "healthy",
        "service": "Khmer Store",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat()
    })


# ============================================================
# Main
# ============================================================

if __name__ == "__main__":
    local_ip = get_local_ip()

    print("=" * 60)
    print(" Khmer Store - SECURE VERSION")
    print("=" * 60)
    print(f" Local:   http://127.0.0.1")
    print(f" Network: http://{local_ip}")
    print("=" * 60)

    app.run(
        host="0.0.0.0",
        port=80,
        debug=False  # SECURE: Debug mode disabled
    )
