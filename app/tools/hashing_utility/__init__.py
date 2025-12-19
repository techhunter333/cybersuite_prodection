from flask import Blueprint

bp = Blueprint(
    'hashing_utility', 
    __name__,
    template_folder='templates',
    static_folder='static',
    url_prefix='/hashing-utility'
)

# [FIX] Correct relative import
from . import routes