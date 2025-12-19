from flask import Blueprint

bp = Blueprint('threat_news', 
               __name__, 
               url_prefix='/threat-news',
               static_folder='static', 
               template_folder='templates')

from . import routes