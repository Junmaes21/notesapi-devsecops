import pytest

from app import create_app

CLAVE = "clave-segura-1"


@pytest.fixture
def client(tmp_path):
    app = create_app(db_path=str(tmp_path / "test.db"), secret_key="test-key")
    return app.test_client()


def registrar(client, usuario="ana_01", clave=CLAVE):
    return client.post("/register", json={"username": usuario, "password": clave})


def entrar(client, usuario="ana_01", clave=CLAVE):
    return client.post("/login", json={"username": usuario, "password": clave})


def test_pagina_inicio(client):
    r = client.get("/")
    assert r.status_code == 200
    assert b"NotesAPI" in r.data


def test_health(client):
    assert client.get("/health").json == {"status": "ok"}


def test_login_usuario_demo(client):
    r = entrar(client, "demo", "demo123")
    assert r.status_code == 200
    assert r.json["username"] == "demo"


def test_login_incorrecto(client):
    assert entrar(client, "demo", "mala").status_code == 401


def test_me_sin_sesion(client):
    assert client.get("/me").status_code == 401


def test_registro_y_login(client):
    assert registrar(client).status_code == 201
    assert entrar(client).status_code == 200
    assert client.get("/me").json["username"] == "ana_01"


def test_registro_duplicado(client):
    registrar(client)
    assert registrar(client).status_code == 409


def test_registro_valida_datos(client):
    assert registrar(client, usuario="a b").status_code == 400
    assert registrar(client, clave="corta").status_code == 400


def test_notas_requieren_sesion(client):
    assert client.get("/notes").status_code == 401
    assert client.post("/notes", json={"title": "x"}).status_code == 401


def test_crud_de_notas(client):
    registrar(client)
    entrar(client)
    r = client.post("/notes", json={"title": "Compras", "body": "leche y pan"})
    assert r.status_code == 201
    nota_id = r.json["id"]
    assert len(client.get("/notes").json) == 1
    assert len(client.get("/notes?q=leche").json) == 1
    assert client.get("/notes?q=zzz").json == []
    r = client.put(f"/notes/{nota_id}", json={"title": "Compras 2", "body": "huevos"})
    assert r.status_code == 200
    assert client.get("/notes").json[0]["title"] == "Compras 2"
    assert client.delete(f"/notes/{nota_id}").status_code == 200
    assert client.get("/notes").json == []


def test_nota_requiere_titulo(client):
    registrar(client)
    entrar(client)
    assert client.post("/notes", json={"title": "  ", "body": "x"}).status_code == 400


def test_notas_son_privadas(client):
    registrar(client, "ana_01")
    entrar(client, "ana_01")
    nota_id = client.post("/notes", json={"title": "secreta", "body": "x"}).json["id"]

    otro = client.application.test_client()
    registrar(otro, "beto_02", CLAVE)
    entrar(otro, "beto_02", CLAVE)
    assert otro.get("/notes").json == []
    assert otro.delete(f"/notes/{nota_id}").status_code == 404
    assert otro.put(f"/notes/{nota_id}", json={"title": "x", "body": ""}).status_code == 404


def test_logout(client):
    registrar(client)
    entrar(client)
    assert client.post("/logout").status_code == 200
    assert client.get("/me").status_code == 401


def test_login_bloquea_sql_injection(client):
    r = client.post("/login", json={"username": "demo' --", "password": "x"})
    assert r.status_code == 401
