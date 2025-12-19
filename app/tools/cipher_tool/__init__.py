from flask import Blueprint

bp = Blueprint(
    'cipher_tool', 
    __name__,
    template_folder='templates',
    static_folder='static',
    url_prefix='/cipher-tool'
)

# [THE FIX] This now correctly imports the routes from this same folder.
from . import routes