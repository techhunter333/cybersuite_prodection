from flask import Blueprint

bp = Blueprint('whois_lookup', 
               __name__, 
               url_prefix='/whois-lookup', 
               template_folder='templates')

from . import routes