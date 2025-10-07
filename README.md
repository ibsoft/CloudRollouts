# Update Server — Flask MVP

Multi-tenant update server για στόλους Windows. Admin UI (Bootstrap), agent API, artifacts με Range streaming, health/ready, metrics, Swagger, rate-limits, scheduler.

## Dev quick start
```bash
python -m venv .venv
source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
python manage.py db-init or flask db upgrade
flask --app wsgi:app run -h 0.0.0.0 -p 8080
```
- Admin UI: http://localhost:8080/
- Swagger:    /apidocs
- Health:     /health
- Ready:      /ready
- Metrics:    /metrics



<img width="1895" height="949" alt="image" src="https://github.com/user-attachments/assets/45325108-f677-4dab-8f01-0bf686998cbc" />

<img width="1895" height="949" alt="image" src="https://github.com/user-attachments/assets/377129dc-9eb8-4352-b492-60e5af393245" />

<img width="1895" height="949" alt="image" src="https://github.com/user-attachments/assets/6ce0d385-b34e-42c8-8a46-17d9fd5882e7" />

<img width="1895" height="949" alt="image" src="https://github.com/user-attachments/assets/78023a3e-568e-47c4-91aa-32987d8e0722" />

<img width="1895" height="949" alt="image" src="https://github.com/user-attachments/assets/f1d52ce2-d20a-4792-8866-8ecec2380477" />

<img width="1895" height="949" alt="image" src="https://github.com/user-attachments/assets/31a822ee-e5d3-4412-8176-25fe44f7a99a" />

<img width="1895" height="949" alt="image" src="https://github.com/user-attachments/assets/a5f90834-ad27-4aab-bb57-43fd9e5a94ef" />






