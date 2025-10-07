# update_server/billing/__init__.py
from flask import Blueprint

# The blueprint serves templates from this folder:
# update_server/billing/templates/
billing_bp = Blueprint("billing", __name__, template_folder="templates")

# Order matters: import the API/JSON routes first, then the Admin UI routes.
from . import routes            # noqa: E402,F401
from . import routes_admin_ui   # noqa: E402,F401
