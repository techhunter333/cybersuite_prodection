from flask import Blueprint

bp = Blueprint(
    'password_strength', 
    __name__,
    template_folder='templates',
    static_folder='static',
    url_prefix='/password-strength'
)

# [THE FIX] This now correctly imports the routes from this same folder.
from . import routes