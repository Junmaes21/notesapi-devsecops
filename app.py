"""NotesAPI - version VULNERABLE (solo con fines educativos)."""
import sqlite3

from flask import Flask, jsonify, request, session

# FALLO 2: secreto escrito directamente en el codigo fuente
API_SECRET_KEY = "a8f5f167f44f4964e6c998dee827110c3b1f7e9d"
# (ese mismo secreto firma las cookies de sesion: quien lo lea puede falsificarlas)


def run(path, sql, params=(), want_id=False):
    """Ejecuta una consulta SQL y devuelve las filas (o el id insertado)."""
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        cur = conn.execute(sql, params)
        rows = cur.fetchall()
        conn.commit()
        return cur.lastrowid if want_id else rows
    finally:
        conn.close()


def init_db(path):
    run(path, "CREATE TABLE IF NOT EXISTS users "
              "(id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)")
    run(path, "CREATE TABLE IF NOT EXISTS notes "
              "(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, title TEXT NOT NULL, "
              "body TEXT NOT NULL DEFAULT '', created_at TEXT DEFAULT CURRENT_TIMESTAMP)")
    run(path, "INSERT OR IGNORE INTO users (username, password) "
              "VALUES ('demo', 'demo123')")


def valid_username(name):
    return 3 <= len(name) <= 30 and name.isascii() and name.replace("_", "").isalnum()


def clean_note(data):
    title = str(data.get("title", "")).strip()
    body = str(data.get("body", "")).strip()
    if not title or len(title) > 100 or len(body) > 5000:
        return None
    return title, body


def need_login():
    return jsonify(error="inicia sesion"), 401


def create_app(db_path="notes.db", secret_key=API_SECRET_KEY):
    app = Flask(__name__)
    app.secret_key = secret_key
    app.config.update(SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_HTTPONLY=True)
    init_db(db_path)

    @app.get("/")
    def home():
        return app.send_static_file("index.html")

    @app.get("/health")
    def health():
        return jsonify(status="ok")

    @app.get("/me")
    def me():
        if not session.get("user_id"):
            return jsonify(error="no autenticado"), 401
        return jsonify(user_id=session["user_id"], username=session.get("username"))

    @app.post("/register")
    def register():
        data = request.get_json(silent=True) or {}
        username = str(data.get("username", "")).strip()
        password = str(data.get("password", ""))
        if not valid_username(username):
            return jsonify(error="usuario: 3 a 30 caracteres (letras, numeros y _)"), 400
        if not 8 <= len(password) <= 128:
            return jsonify(error="contrasena: entre 8 y 128 caracteres"), 400
        try:
            run(db_path, "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, password))
        except sqlite3.IntegrityError:
            return jsonify(error="ese usuario ya existe"), 409
        return jsonify(status="creado"), 201

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
        session.clear()
        session["user_id"] = rows[0]["id"]
        session["username"] = rows[0]["username"]
        return jsonify(user_id=rows[0]["id"], username=rows[0]["username"])

    @app.post("/logout")
    def logout():
        session.clear()
        return jsonify(status="ok")

    @app.get("/notes")
    def list_notes():
        uid = session.get("user_id")
        if not uid:
            return need_login()
        q = "%" + request.args.get("q", "").strip() + "%"
        rows = run(db_path,
                   "SELECT id, title, body, created_at FROM notes "
                   "WHERE user_id = ? AND (title LIKE ? OR body LIKE ?) ORDER BY id DESC",
                   (uid, q, q))
        return jsonify([dict(r) for r in rows])

    @app.post("/notes")
    def create_note():
        uid = session.get("user_id")
        if not uid:
            return need_login()
        note = clean_note(request.get_json(silent=True) or {})
        if note is None:
            return jsonify(error="titulo obligatorio (max 100) y texto de max 5000"), 400
        title, body = note
        note_id = run(db_path, "INSERT INTO notes (user_id, title, body) VALUES (?, ?, ?)",
                      (uid, title, body), want_id=True)
        return jsonify(id=note_id, title=title, body=body), 201

    @app.put("/notes/<int:note_id>")
    def update_note(note_id):
        uid = session.get("user_id")
        if not uid:
            return need_login()
        note = clean_note(request.get_json(silent=True) or {})
        if note is None:
            return jsonify(error="titulo obligatorio (max 100) y texto de max 5000"), 400
        if not run(db_path, "SELECT id FROM notes WHERE id = ? AND user_id = ?",
                   (note_id, uid)):
            return jsonify(error="nota no encontrada"), 404
        title, body = note
        run(db_path, "UPDATE notes SET title = ?, body = ? WHERE id = ? AND user_id = ?",
            (title, body, note_id, uid))
        return jsonify(id=note_id, title=title, body=body)

    @app.delete("/notes/<int:note_id>")
    def delete_note(note_id):
        uid = session.get("user_id")
        if not uid:
            return need_login()
        if not run(db_path, "SELECT id FROM notes WHERE id = ? AND user_id = ?",
                   (note_id, uid)):
            return jsonify(error="nota no encontrada"), 404
        run(db_path, "DELETE FROM notes WHERE id = ? AND user_id = ?", (note_id, uid))
        return jsonify(status="eliminada")

    return app


app = create_app()

if __name__ == "__main__":
    app.run(port=5000)
