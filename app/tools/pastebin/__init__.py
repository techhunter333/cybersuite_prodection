from flask import Blueprint

bp = Blueprint(
    'pastebin', 
    __name__,
    template_folder='templates',
    static_folder='static',
    url_prefix='/pastebin'
)

# --- THIS IS THE FIX ---
# Import the routes module so Flask discovers your @bp.route decorators
from . import routes

# Now, also explicitly import the functions your main app needs
from .routes import close_db, init_db_command
# --- END OF FIX ---