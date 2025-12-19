from flask import Blueprint

bp = Blueprint(
    'redirect_checker', 
    __name__,
    template_folder='templates',
    static_folder='static',
    url_prefix='/redirect-checker'
)

# [FIX] Correct relative import for v2 structure
from . import routes