"""
Khmer Store — Vulnerable Web Application (Security Lab)

THIS APPLICATION INTENTIONALLY CONTAINS SECURITY VULNERABILITIES.
DO NOT DEPLOY IN PRODUCTION. FOR EDUCATIONAL PURPOSES ONLY.

Run: python app.py
Access: http://localhost:80
"""

from flask import Flask, request, jsonify, session, render_template, redirect, url_for
from functools import wraps
import re
import os
import secrets
import socket
import sqlite3
from datetime import datetime
from database import (
    init_db, get_db, hash_password, verify_password, get_user_by_username,
    get_user_by_id, create_user, update_user_verified, update_user_name,
    update_user_role, update_user_profile, get_all_users, get_all_products,
    get_product_by_id, get_orders, get_user_orders, create_order, get_stats
)

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

init_db()

REQUEST_LOG = []


@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def log_request(method, path, status_code, details=""):
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
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            if request.is_json:
                return jsonify({"error": "Login required"}), 401
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
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


# ============================================================
# Page Routes
# ============================================================

@app.route("/")
def index():
    log_request("GET", "/", 200)
    products = get_all_products()[:6]
    return render_template("index.html", products=products)


@app.route("/products")
def products_page():
    log_request("GET", "/products", 200)
    products = get_all_products()
    return render_template("products.html", products=products)


@app.route("/register")
def register_page():
    log_request("GET", "/register", 200)
    return render_template("register.html")


@app.route("/login")
def login_page():
    log_request("GET", "/login", 200)
    return render_template("login.html")


@app.route("/verify")
def verify_page():
    log_request("GET", "/verify", 200)
    return render_template("verify.html")


@app.route("/account")
@login_required
def account_page():
    log_request("GET", "/account", 200)
    user = get_user_by_id(session["user_id"])
    orders = get_user_orders(session["user_id"])
    return render_template("account.html", user=user, orders=orders)


@app.route("/profile")
@login_required
def profile_page():
    log_request("GET", "/profile", 200)
    user = get_user_by_id(session["user_id"])
    return render_template("profile.html", user=user)


@app.route("/admin")
@admin_required
def admin_page():
    log_request("GET", "/admin", 200)
    user = get_user_by_id(session["user_id"])
    stats = get_stats()
    users = get_all_users()
    return render_template("admin.html", user=user, stats=stats, users=users)


# ============================================================
# API Routes - Registration
# ============================================================

@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json()

    if not data:
        log_request("POST", "/api/register", 400, "Missing JSON body")
        return jsonify({"error": "Request body required"}), 400

    username = data.get("username", "").strip()
    email = data.get("email", "").strip()
    password = data.get("password", "")
    name = data.get("name", "").strip()

    if not username or not email or not password or not name:
        log_request("POST", "/api/register", 400, "Missing required fields")
        return jsonify({"error": "All fields are required"}), 400

    if len(password) < 1:
        log_request("POST", "/api/register", 400, "Password too short")
        return jsonify({"error": "Password is required"}), 400

    result = create_user(username, email, password, name)
    if not result:
        log_request("POST", "/api/register", 409, f"Username or email exists")
        return jsonify({"error": "Username or email already exists"}), 409

    log_request("POST", "/api/register", 201, f"User {username} registered")
    return jsonify({
        "success": True,
        "message": "Account created successfully",
        "username": username,
        "verification_code": result["verification_code"],
        "note": "Use this code to verify your account."
    }), 201


# ============================================================
# API Routes - Verification
# ============================================================

@app.route("/api/verify", methods=["POST"])
def api_verify():
    data = request.get_json()

    if not data:
        log_request("POST", "/api/verify", 400, "Missing JSON body")
        return jsonify({"error": "Request body required"}), 400

    username = data.get("username", "").strip()
    code = data.get("code", "")

    user = get_user_by_username(username)
    if not user:
        log_request("POST", "/api/verify", 404, f"User {username} not found")
        return jsonify({"error": "User not found"}), 404

    if user["verified"]:
        log_request("POST", "/api/verify", 400, f"User {username} already verified")
        return jsonify({"error": "Account already verified"}), 400

    if code == user["verification_code"]:
        update_user_verified(username)
        log_request("POST", "/api/verify", 200, f"User {username} verified with correct code")
        return jsonify({
            "success": True,
            "message": "Account verified successfully",
            "username": username,
            "verified": True
        })
    else:
        log_request("POST", "/api/verify", 401, f"User {username} wrong code")
        return jsonify({
            "success": False,
            "message": "Invalid verification code"
        }), 401


# ============================================================
# API Routes - Login
# ============================================================

@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json()

    if not data:
        log_request("POST", "/api/login", 400, "Missing JSON body")
        return jsonify({"error": "Request body required"}), 400

    username = data.get("username", "").strip()
    password = data.get("password", "")

    user = get_user_by_username(username)
    if not user or not verify_password(password, user["password_hash"]):
        log_request("POST", "/api/login", 401, f"Invalid credentials for {username}")
        return jsonify({"error": "Invalid username or password"}), 401

    if not user["verified"]:
        log_request("POST", "/api/login", 403, f"User {username} not verified")
        return jsonify({"error": "Account not verified. Please verify your account first."}), 403

    session.clear()
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["role"] = user["role"]

    log_request("POST", "/api/login", 200, f"User {username} logged in")
    return jsonify({
        "success": True,
        "message": "Login successful",
        "username": username,
        "role": user["role"]
    })


@app.route("/api/logout", methods=["POST"])
def api_logout():
    username = session.pop("username", None)
    session.pop("user_id", None)
    session.pop("role", None)
    session.clear()
    log_request("POST", "/api/logout", 200, f"User {username} logged out")
    return jsonify({"success": True, "message": "Logged out"})


# ============================================================
# API Routes - Profile
# ============================================================

@app.route("/api/profile", methods=["GET"])
@login_required
def get_profile():
    user = get_user_by_id(session["user_id"])
    log_request("GET", "/api/profile", 200, f"Profile retrieved for {user['username']}")
    return jsonify({
        "id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "name": user["name"],
        "role": user["role"],
        "verified": bool(user["verified"])
    })


# ============================================================
# API Routes - User by ID  [VULNERABILITY: IDOR + Information Disclosure]
# ============================================================

@app.route("/api/users/<int:user_id>", methods=["GET"])
@login_required
def get_user_by_id_endpoint(user_id):
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
        "created_at": user["created_at"],
        "password_hash": user["password_hash"],
        "verification_code": user["verification_code"]
    })


@app.route("/api/profile/name", methods=["POST"])
@login_required
def update_name():
    data = request.get_json()
    if not data:
        log_request("POST", "/api/profile/name", 400, "Missing JSON body")
        return jsonify({"error": "Request body required"}), 400

    name = data.get("name", "")
    if not name:
        log_request("POST", "/api/profile/name", 400, "Missing name")
        return jsonify({"error": "Name is required"}), 400

    update_user_name(session["user_id"], name)

    log_request("POST", "/api/profile/name", 200,
                f"User {session['username']} name updated to: {name}")

    return jsonify({
        "success": True,
        "display_name": name,
        "note": "Name updated"
    })


# ============================================================
# API Routes - Account Update  [VULNERABILITY: Mass Assignment]
# ============================================================

@app.route("/api/account/update", methods=["POST"])
@login_required
def update_account():
    data = request.get_json()
    if not data:
        log_request("POST", "/api/account/update", 400, "Missing JSON body")
        return jsonify({"error": "Request body required"}), 400

    name = data.get("name", "").strip()
    email = data.get("email", "").strip()
    role = data.get("role", "").strip()

    user = get_user_by_id(session["user_id"])
    if not user:
        log_request("POST", "/api/account/update", 404, "User not found")
        return jsonify({"error": "User not found"}), 404

    update_user_profile(session["user_id"], name=name if name else None, email=email if email else None)

    if role:
        update_user_role(session["user_id"], role)

    updated_user = get_user_by_id(session["user_id"])

    log_request("POST", "/api/account/update", 200,
                f"User {user['username']} profile updated")

    return jsonify({
        "success": True,
        "message": "Account updated successfully",
        "name": name or user["name"],
        "email": email or user["email"],
        "role": updated_user["role"]
    })


# ============================================================
# API Routes - Products
# ============================================================

@app.route("/api/products", methods=["GET"])
def get_products():
    log_request("GET", "/api/products", 200)
    products = get_all_products()
    return jsonify({"products": products, "total": len(products)})


@app.route("/api/products/<int:product_id>", methods=["GET"])
def get_product(product_id):
    log_request("GET", f"/api/products/{product_id}", 200)
    product = get_product_by_id(product_id)
    if not product:
        return jsonify({"error": "Product not found"}), 404
    return jsonify(product)


# ============================================================
# API Routes - Product Search  [VULNERABILITY: SQL Injection]
# ============================================================

@app.route("/api/products/search", methods=["GET"])
def search_products():
    query = request.args.get("q", "")
    category = request.args.get("category", "")

    conn = get_db()
    cursor = conn.cursor()

    if query:
        sql = f"SELECT * FROM products WHERE name LIKE '%{query}%'"
        cursor.execute(sql)
    elif category:
        sql = f"SELECT * FROM products WHERE category = '{category}'"
        cursor.execute(sql)
    else:
        cursor.execute("SELECT * FROM products")

    products = [dict(row) for row in cursor.fetchall()]
    conn.close()

    log_request("GET", f"/api/products/search?q={query}", 200, f"Found {len(products)} products")
    return jsonify({"products": products, "total": len(products)})


# ============================================================
# API Routes - Reviews  [VULNERABILITY: Stored XSS]
# ============================================================

REVIEWS = []


@app.route("/api/products/<int:product_id>/reviews", methods=["POST"])
@login_required
def add_review(product_id):
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body required"}), 400

    review_text = data.get("review", "")
    rating = data.get("rating", 5)

    review = {
        "id": len(REVIEWS) + 1,
        "product_id": product_id,
        "user_id": session["user_id"],
        "username": session["username"],
        "review": review_text,
        "rating": rating,
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    REVIEWS.append(review)

    log_request("POST", f"/api/products/{product_id}/reviews", 201, f"Review added by {session['username']}")
    return jsonify({"success": True, "message": "Review added", "review": review}), 201


@app.route("/api/products/<int:product_id>/reviews", methods=["GET"])
def get_reviews(product_id):
    product_reviews = [r for r in REVIEWS if r["product_id"] == product_id]
    log_request("GET", f"/api/products/{product_id}/reviews", 200)
    return jsonify({"reviews": product_reviews, "total": len(product_reviews)})


# ============================================================
# API Routes - Orders
# ============================================================

@app.route("/api/orders", methods=["POST"])
@login_required
def create_new_order():
    data = request.get_json()
    if not data:
        log_request("POST", "/api/orders", 400, "Missing JSON body")
        return jsonify({"error": "Request body required"}), 400

    product_id = data.get("product_id")
    quantity = data.get("quantity", 1)

    product = get_product_by_id(product_id)
    if not product:
        log_request("POST", "/api/orders", 404, "Product not found")
        return jsonify({"error": "Product not found"}), 404

    if product["stock"] < quantity:
        log_request("POST", "/api/orders", 400, "Insufficient stock")
        return jsonify({"error": "Insufficient stock"}), 400

    total = product["price"] * quantity
    order_id = create_order(session["user_id"], product_id, quantity, total)

    log_request("POST", "/api/orders", 201, f"Order {order_id} created")

    return jsonify({
        "success": True,
        "message": "Order created successfully",
        "order_id": order_id,
        "product": product["name"],
        "quantity": quantity,
        "total": total
    }), 201


@app.route("/api/orders", methods=["GET"])
@login_required
def get_user_orders_list():
    log_request("GET", "/api/orders", 200)
    orders = get_user_orders(session["user_id"])
    return jsonify({"orders": orders, "total": len(orders)})


# ============================================================
# API Routes - Order by ID  [VULNERABILITY: IDOR on Orders]
# ============================================================

@app.route("/api/orders/<int:order_id>", methods=["GET"])
@login_required
def get_order_by_id(order_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT o.*, u.username, p.name as product_name, p.price
        FROM orders o
        JOIN users u ON o.user_id = u.id
        JOIN products p ON o.product_id = p.id
        WHERE o.id = ?
    """, (order_id,))
    order = cursor.fetchone()
    conn.close()

    if not order:
        log_request("GET", f"/api/orders/{order_id}", 404, "Order not found")
        return jsonify({"error": "Order not found"}), 404

    log_request("GET", f"/api/orders/{order_id}", 200, f"Order {order_id} retrieved")
    return jsonify(dict(order))


@app.route("/api/orders/<int:order_id>", methods=["DELETE"])
@login_required
def delete_order(order_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM orders WHERE id = ?", (order_id,))
    conn.commit()
    conn.close()

    log_request("DELETE", f"/api/orders/{order_id}", 200, f"Order {order_id} deleted")
    return jsonify({"success": True, "message": "Order deleted"})


# ============================================================
# API Routes - Admin
# ============================================================

@app.route("/api/admin/stats", methods=["GET"])
@admin_required
def admin_stats():
    log_request("GET", "/api/admin/stats", 200)
    stats = get_stats()
    return jsonify(stats)


@app.route("/api/admin/users", methods=["GET"])
@admin_required
def admin_users():
    log_request("GET", "/api/admin/users", 200)
    users = get_all_users()
    return jsonify({"users": users, "total": len(users)})


@app.route("/api/admin/orders", methods=["GET"])
@admin_required
def admin_orders():
    log_request("GET", "/api/admin/orders", 200)
    orders = get_orders()
    return jsonify({"orders": orders, "total": len(orders)})


# ============================================================
# API Routes - Logs  [VULNERABILITY: Unauthenticated Access]
# ============================================================

@app.route("/api/logs", methods=["GET"])
def get_logs():
    log_request("GET", "/api/logs", 200)
    return jsonify({
        "logs": REQUEST_LOG[-50:],
        "total": len(REQUEST_LOG)
    })


# ============================================================
# Health Check  [VULNERABILITY: Information Disclosure]
# ============================================================

@app.route("/health")
def health():
    log_request("GET", "/health", 200)
    return jsonify({
        "status": "healthy",
        "service": "Khmer Store",
        "version": "2.0.0",
        "timestamp": datetime.now().isoformat(),
        "debug": True,
        "secret_key": app.secret_key,
        "server_ip": get_local_ip(),
        "database": "khmer_store.db",
        "python_version": "3.14.6",
        "flask_version": "3.1.8",
        "session_config": {
            "secure": app.config['SESSION_COOKIE_SECURE'],
            "httponly": app.config['SESSION_COOKIE_HTTPONLY'],
            "samesite": app.config['SESSION_COOKIE_SAMESITE']
        }
    })


# ============================================================
# Main
# ============================================================

if __name__ == "__main__":
    local_ip = get_local_ip()

    print("=" * 60)
    print("  Khmer Store — Vulnerable Lab")
    print(f"  Local:   http://localhost:5000")
    print(f"  Network: http://{local_ip}:5000")
    print("=" * 60)

    app.run(
        host="0.0.0.0",
        port=80,
        debug=True
    )
