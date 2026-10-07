"""NotesAPI - version CORREGIDA."""
import hmac
import os
import sqlite3

from flask import Flask, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash


def run(path, sql, params=()):
    """Ejecuta una consulta SQL parametrizada y devuelve las filas."""
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(sql, params).fetchall()
        conn.commit()
        return rows
    finally:
        conn.close()


def init_db(path):
    run(path, "CREATE TABLE IF NOT EXISTS users "
              "(id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)")
    run(path, "CREATE TABLE IF NOT EXISTS notes "
              "(id INTEGER PRIMARY KEY, user_id INTEGER, text TEXT)")
    run(path, "INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)",
        ("demo", generate_password_hash("demo123")))


def create_app(db_path="notes.db", api_key=None):
    app = Flask(__name__)
    init_db(db_path)
    # CORRECCION 2: el secreto viene de una variable de entorno
    key = api_key or os.environ.get("API_SECRET_KEY", "")

    def authorized():
        sent = request.headers.get("X-API-Key", "")
        return bool(key) and hmac.compare_digest(sent, key)

    @app.get("/health")
    def health():
        return jsonify(status="ok")

    @app.post("/login")
    def login():
        data = request.get_json(silent=True) or {}
        username = data.get("username", "")
        password = data.get("password", "")
        # CORRECCION 1: consulta parametrizada, el input nunca es parte del SQL
        rows = run(db_path,
                   "SELECT id, username, password FROM users WHERE username = ?",
                   (username,))
        if not rows or not check_password_hash(rows[0]["password"], password):
            return jsonify(error="credenciales invalidas"), 401
        return jsonify(user_id=rows[0]["id"], username=rows[0]["username"])

    @app.get("/notes")
    def list_notes():
        if not authorized():
            return jsonify(error="no autorizado"), 401
        user_id = request.args.get("user_id", type=int)
        rows = run(db_path, "SELECT id, text FROM notes WHERE user_id = ?", (user_id,))
        return jsonify([dict(r) for r in rows])

    @app.post("/notes")
    def create_note():
        if not authorized():
            return jsonify(error="no autorizado"), 401
        data = request.get_json(silent=True) or {}
        run(db_path, "INSERT INTO notes (user_id, text) VALUES (?, ?)",
            (data.get("user_id"), data.get("text", "")))
        return jsonify(status="creada"), 201

    return app


app = create_app()

if __name__ == "__main__":
    app.run(port=5000)
