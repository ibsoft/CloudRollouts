__version__ = "11.0.0"

# app/__init__.py
from update_server.version import __version__ as APP_VER
from flask import Flask, g

def create_app():
    app = Flask(__name__)
    app.config["APP_VERSION"] = APP_VER

    @app.before_request
    def inject_version():
        g.app_version = APP_VER
    return app
