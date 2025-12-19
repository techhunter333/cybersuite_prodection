from flask import Blueprint

bp = Blueprint(
    'hash_cracker', 
    __name__,
    template_folder='templates',
    static_folder='static',
    url_prefix='/hash-cracker'
)

# [FIX] Correct relative import
from . import routes