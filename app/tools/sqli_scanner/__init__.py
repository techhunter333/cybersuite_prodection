from flask import Blueprint

bp = Blueprint('sqli_scanner', 
               __name__, 
               url_prefix='/sqli-scanner', 
               template_folder='templates')

from . import routes