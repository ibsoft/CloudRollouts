# Update Server — Flask MVP

Multi-tenant update server για στόλους Windows. Admin UI (Bootstrap), agent API, artifacts με Range streaming, health/ready, metrics, Swagger, rate-limits, scheduler.

## Dev quick start
```bash
python -m venv .venv
source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
python manage.py db-init
python manage.py seed
flask --app wsgi:app run -h 0.0.0.0 -p 8080
```
- Admin UI: http://localhost:8080/
- Swagger:    /apidocs
- Health:     /health
- Ready:      /ready
- Metrics:    /metrics
