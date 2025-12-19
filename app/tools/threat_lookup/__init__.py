from flask import Blueprint

bp = Blueprint('threat_lookup', 
               __name__, 
               url_prefix='/threat-lookup',
               static_folder='static', 
               template_folder='templates')

from . import routes