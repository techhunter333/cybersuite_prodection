from flask import Blueprint

bp = Blueprint(
    'steganography', 
    __name__,
    template_folder='templates',
    static_folder='static',
    url_prefix='/steganography'
)

# [FIX] Correct relative import
from . import routes