from flask import Blueprint

bp = Blueprint('qr_generator', 
               __name__, 
               url_prefix='/qr-generator', 
               template_folder='templates')

from . import routes