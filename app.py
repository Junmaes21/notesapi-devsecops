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


HOME = """<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NotesAPI</title>
<style>
body { font-family: system-ui, sans-serif; max-width: 560px; margin: 2rem auto;
       padding: 0 1rem; color: #222; }
input, button { font: inherit; padding: .5rem; margin: .25rem 0; }
input { width: 100%; box-sizing: border-box; }
button { cursor: pointer; margin-right: .5rem; }
pre { background: #f4f4f4; padding: 1rem; border-radius: 6px; overflow-x: auto; }
.tag { background: #eef; padding: .1rem .5rem; border-radius: 4px; font-size: .85rem; }
</style>
</head>
<body>
<h1>NotesAPI</h1>
<p><span class="tag">version corregida</span></p>
<p>API de notas usada para demostrar escaneo de vulnerabilidades automatizado
(Bandit, Gitleaks, pip-audit y Grype) con GitHub Actions.</p>
<h2>Probar el login</h2>
<p>Usuario de prueba: <b>demo</b> / <b>demo123</b></p>
<input id="u" placeholder="usuario">
<input id="p" type="password" placeholder="contrasena">
<button onclick="enviar(u.value, p.value)">Entrar</button>
<button onclick="enviar('demo' + String.fromCharCode(39) + ' --', 'x')">
Probar SQL injection</button>
<pre id="out">Respuesta de la API...</pre>
<p>Rutas: <code>GET /health</code>, <code>POST /login</code>,
<code>GET|POST /notes</code> (requiere clave de API).</p>
<script>
async function enviar(usuario, clave) {
  const r = await fetch('/login', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({username: usuario, password: clave})
  });
  document.getElementById('out').textContent =
    r.status + ' ' + JSON.stringify(await r.json(), null, 2);
}
</script>
</body>
</html>
"""


def create_app(db_path="notes.db", api_key=None):
    app = Flask(__name__)
    init_db(db_path)
    # CORRECCION 2: el secreto viene de una variable de entorno
    key = api_key or os.environ.get("API_SECRET_KEY", "")

    def authorized():
        sent = request.headers.get("X-API-Key", "")
        return bool(key) and hmac.compare_digest(sent, key)

    @app.get("/")
    def home():
        return HOME

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
