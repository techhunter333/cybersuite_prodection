from flask import Blueprint

bp = Blueprint('encoder_decoder', 
               __name__, 
               url_prefix='/encoder-decoder',
               static_folder='static', 
               template_folder='templates')

from . import routes