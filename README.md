# NotesAPI DevSecOps

Aplicación de notas en Flask para demostrar **escaneo de vulnerabilidades automatizado** con GitHub Actions.

- **App:** https://notesapi-devsecops.onrender.com
- **Artículo:** https://medium.com/@juniormaes21/cazando-vulnerabilidades-en-cada-push-bandit-gitleaks-pip-audit-y-grype-en-github-actions-955cac68ed33?sharedUserId=juniormaes21

## Ramas

- **`vulnerable`**: tres fallos a propósito (SQL injection, clave en el código y dependencias antiguas). El pipeline falla y no se despliega.
- **`fixed`**: los tres fallos corregidos. El pipeline pasa y se despliega en Render.

## Pipeline

En cada push, GitHub Actions ejecuta ruff y pytest, y en paralelo cuatro escáneres:

- **Bandit**: código Python (lista de OWASP)
- **Grype**: dependencias (lista de OWASP)
- **Gitleaks**: secretos en el historial
- **pip-audit**: dependencias

El despliegue en Render solo ocurre en `fixed` y solo si todo pasa.

## Ejecutar en local

```bash
git checkout fixed
pip install -r requirements-dev.txt
pytest -q
python app.py
```

Usuario de prueba: `demo` / `demo123`.

## Licencia

MIT
