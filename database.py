"""
Khmer Store — Database module using SQLite
"""

import sqlite3
import os
import secrets
import string
import bcrypt
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "khmer_store.db")


def get_db():
    """Get database connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize database with tables and sample data."""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            name TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            verified INTEGER DEFAULT 0,
            verification_code TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            price REAL NOT NULL,
            category TEXT,
            stock INTEGER DEFAULT 100,
            image_url TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            product_id INTEGER,
            quantity INTEGER DEFAULT 1,
            total REAL NOT NULL,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (product_id) REFERENCES products(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cart (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            product_id INTEGER,
            quantity INTEGER DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (product_id) REFERENCES products(id)
        )
    """)

    cursor.execute("SELECT COUNT(*) FROM products")
    if cursor.fetchone()[0] == 0:
        fake_users = [
            ("sokha", "sokha@example.com", hash_password("password123"), "Sokha", "user", 1),
            ("bopha", "bopha@example.com", hash_password("password123"), "Bopha", "user", 1),
            ("dara", "dara@example.com", hash_password("password123"), "Dara", "admin", 1),
            ("chantha", "chantha@example.com", hash_password("password123"), "Chantha", "user", 1),
            ("sophea", "sophea@example.com", hash_password("password123"), "Sophea", "user", 1),
        ]
        cursor.executemany(
            "INSERT INTO users (username, email, password_hash, name, role, verified) VALUES (?, ?, ?, ?, ?, ?)",
            fake_users
        )

        products = [
            ("Wireless Mouse", "Ergonomic wireless mouse with adjustable DPI. Compatible with Windows and macOS.", 29.99, "Electronics", 150, "/static/mouse.svg"),
            ("Mechanical Keyboard", "RGB mechanical keyboard with blue switches. Full-size layout with numpad.", 79.99, "Electronics", 85, "/static/keyboard.svg"),
            ("USB-C Hub", "7-in-1 USB-C hub with HDMI, USB 3.0, SD card reader, and power delivery.", 45.99, "Accessories", 200, "/static/hub.svg"),
            ("Laptop Stand", "Adjustable aluminum laptop stand. Ergonomic design for better posture.", 34.99, "Accessories", 120, "/static/stand.svg"),
            ("Webcam HD", "1080p HD webcam with built-in microphone. Perfect for video calls.", 59.99, "Electronics", 95, "/static/webcam.svg"),
            ("Security Book", "Practical guide to web application security. Covers OWASP Top 10.", 49.99, "Books", 75, "/static/book.svg"),
            ("Headphones", "Noise-cancelling wireless headphones. 30-hour battery life.", 89.99, "Electronics", 60, "/static/headphones.svg"),
            ("Monitor Light", "LED monitor light bar. Reduces eye strain with adjustable brightness.", 39.99, "Accessories", 110, "/static/light.svg"),
            ("Desk Mat", "Large desk mat for keyboard and mouse. Non-slip rubber base.", 19.99, "Accessories", 180, "/static/deskmat.svg"),
            ("Power Bank", "20000mAh power bank with fast charging. Dual USB output.", 44.99, "Electronics", 130, "/static/powerbank.svg"),
            ("HDMI Cable", "6ft 4K HDMI cable. High-speed with Ethernet support.", 12.99, "Accessories", 250, "/static/cable.svg"),
            ("USB Flash Drive", "128GB USB 3.0 flash drive. Fast data transfer speeds.", 18.99, "Accessories", 300, "/static/flashdrive.svg"),
            ("Wireless Charger", "15W wireless charging pad. Compatible with Qi-enabled devices.", 24.99, "Electronics", 140, "/static/charger.svg"),
            ("Screen Protector", "Tempered glass screen protector for 15.6 inch laptops.", 9.99, "Accessories", 220, "/static/protector.svg"),
            ("Cable Organizer", "Silicone cable management clips. Pack of 10.", 8.99, "Accessories", 280, "/static/organizer.svg"),
            ("Laptop Sleeve", "Padded laptop sleeve for 14 inch laptops. Water-resistant.", 27.99, "Accessories", 100, "/static/sleeve.svg"),
            ("Bluetooth Speaker", "Portable Bluetooth speaker with 360-degree sound. IPX7 waterproof.", 69.99, "Electronics", 70, "/static/speaker.svg"),
            ("Keyboard Wrist Rest", "Memory foam wrist rest for mechanical keyboards. Ergonomic design.", 15.99, "Accessories", 160, "/static/wristrest.svg"),
        ]
        cursor.executemany(
            "INSERT INTO products (name, description, price, category, stock, image_url) VALUES (?, ?, ?, ?, ?, ?)",
            products
        )

    conn.commit()
    conn.close()


def hash_password(password):
    """Hash password using bcrypt with salt."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def verify_password(password, password_hash):
    """Verify password against bcrypt hash."""
    return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))


def generate_verification_code():
    """Generate a secure 6-digit verification code."""
    return ''.join(secrets.choice(string.digits) for _ in range(6))


def get_user_by_username(username):
    """Get user by username."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    return dict(user) if user else None


def get_user_by_id(user_id):
    """Get user by ID."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    return dict(user) if user else None


def create_user(username, email, password, name):
    """Create a new user with secure verification code."""
    conn = get_db()
    cursor = conn.cursor()
    try:
        verification_code = generate_verification_code()
        cursor.execute(
            "INSERT INTO users (username, email, password_hash, name, verification_code) VALUES (?, ?, ?, ?, ?)",
            (username, email, hash_password(password), name, verification_code)
        )
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()
        return {"id": user_id, "username": username, "verification_code": verification_code}
    except sqlite3.IntegrityError:
        conn.close()
        return None


def update_user_verified(username):
    """Mark user as verified."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET verified = 1 WHERE username = ?", (username,))
    conn.commit()
    conn.close()


def update_user_name(user_id, name):
    """Update user display name."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET name = ? WHERE id = ?", (name, user_id))
    conn.commit()
    conn.close()


def update_user_role(user_id, role):
    """Update user role."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
    conn.commit()
    conn.close()


def update_user_profile(user_id, name=None, email=None):
    """Update user profile fields."""
    conn = get_db()
    cursor = conn.cursor()
    if name:
        cursor.execute("UPDATE users SET name = ? WHERE id = ?", (name, user_id))
    if email:
        cursor.execute("UPDATE users SET email = ? WHERE id = ?", (email, user_id))
    conn.commit()
    conn.close()


def get_all_users():
    """Get all users."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, name, role, verified, created_at FROM users")
    users = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return users


def get_all_products():
    """Get all products."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products")
    products = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return products


def get_product_by_id(product_id):
    """Get product by ID."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    conn.close()
    return dict(product) if product else None


def get_orders():
    """Get all orders with user and product info."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT o.*, u.username, p.name as product_name
        FROM orders o
        JOIN users u ON o.user_id = u.id
        JOIN products p ON o.product_id = p.id
        ORDER BY o.created_at DESC
    """)
    orders = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return orders


def get_user_orders(user_id):
    """Get orders for a specific user."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT o.*, p.name as product_name, p.price
        FROM orders o
        JOIN products p ON o.product_id = p.id
        WHERE o.user_id = ?
        ORDER BY o.created_at DESC
    """, (user_id,))
    orders = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return orders


def create_order(user_id, product_id, quantity, total):
    """Create a new order."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO orders (user_id, product_id, quantity, total) VALUES (?, ?, ?, ?)",
        (user_id, product_id, quantity, total)
    )
    conn.commit()
    order_id = cursor.lastrowid
    conn.close()
    return order_id


def get_stats():
    """Get admin dashboard statistics."""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM users")
    users_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM products")
    products_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM orders")
    orders_count = cursor.fetchone()[0]

    cursor.execute("SELECT COALESCE(SUM(total), 0) FROM orders")
    revenue = cursor.fetchone()[0]

    conn.close()

    return {
        "users": users_count,
        "products": products_count,
        "orders": orders_count,
        "revenue": revenue
    }
