from flask import Blueprint

bp = Blueprint(
    'file_encryptor', 
    __name__,
    template_folder='templates',
    static_folder='static',
    url_prefix='/file-encryptor'
)

# [FIX] Correct relative import
from . import routes