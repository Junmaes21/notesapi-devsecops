import pytest

from app import create_app


@pytest.fixture
def client(tmp_path):
    app = create_app(db_path=str(tmp_path / "test.db"), api_key="test-key")
    return app.test_client()


def test_pagina_inicio(client):
    r = client.get("/")
    assert r.status_code == 200
    assert b"NotesAPI" in r.data


def test_health(client):
    assert client.get("/health").json == {"status": "ok"}


def test_login_correcto(client):
    r = client.post("/login", json={"username": "demo", "password": "demo123"})
    assert r.status_code == 200


def test_login_incorrecto(client):
    r = client.post("/login", json={"username": "demo", "password": "mala"})
    assert r.status_code == 401


def test_notas_requieren_api_key(client):
    assert client.get("/notes?user_id=1").status_code == 401


def test_crear_y_listar_notas(client):
    headers = {"X-API-Key": "test-key"}
    r = client.post("/notes", json={"user_id": 1, "text": "hola"}, headers=headers)
    assert r.status_code == 201
    r = client.get("/notes?user_id=1", headers=headers)
    assert r.json[0]["text"] == "hola"
