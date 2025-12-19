from flask import Blueprint

bp = Blueprint(
    'digital_signature', 
    __name__,
    template_folder='templates',
    static_folder='static',
    url_prefix='/digital-signature'
)

# [FIX] Correct relative import
from . import routes