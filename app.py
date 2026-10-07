"""NotesAPI - version VULNERABLE (solo con fines educativos)."""
import sqlite3

from flask import Flask, jsonify, request

# FALLO 2: secreto escrito directamente en el codigo fuente
API_SECRET_KEY = "a8f5f167f44f4964e6c998dee827110c3b1f7e9d"


def run(path, sql, params=()):
    """Ejecuta una consulta SQL y devuelve las filas."""
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
    run(path, "INSERT OR IGNORE INTO users (username, password) "
              "VALUES ('demo', 'demo123')")


def create_app(db_path="notes.db", api_key=API_SECRET_KEY):
    app = Flask(__name__)
    init_db(db_path)

    def authorized():
        return request.headers.get("X-API-Key") == api_key

    @app.get("/health")
    def health():
        return jsonify(status="ok")

    @app.post("/login")
    def login():
        data = request.get_json(silent=True) or {}
        username = data.get("username", "")
        password = data.get("password", "")
        # FALLO 1: SQL injection, el input del usuario se concatena en la consulta
        query = ("SELECT id, username FROM users WHERE username = '%s' "
                 "AND password = '%s'" % (username, password))
        rows = run(db_path, query)
        if not rows:
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
