from flask import Blueprint

bp = Blueprint(
    'cryptoguard', 
    __name__,
    template_folder='templates',
    static_folder='static',
    url_prefix='/cryptoguard'
)

# [FIXED] Correct import for the new v2 structure
from . import routes