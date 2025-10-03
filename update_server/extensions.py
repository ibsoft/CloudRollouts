from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flasgger import Swagger
from prometheus_flask_exporter import PrometheusMetrics
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect

db = SQLAlchemy()
migrate = Migrate()
jwt = JWTManager()
limiter = Limiter(key_func=get_remote_address, default_limits=[])
login_manager = LoginManager()
csrf = CSRFProtect()
swagger = Swagger(template={
    "swagger": "2.0",
    "info": {"title": "Update Server API", "version": "1.0.0"},
    "securityDefinitions": {
        "Bearer": {"type": "apiKey", "name": "Authorization", "in": "header", "description": "Bearer <token>"},
        "ApiKey": {"type": "apiKey", "name": "X-API-Key", "in": "header"}
    }
})
metrics = PrometheusMetrics.for_app_factory()
