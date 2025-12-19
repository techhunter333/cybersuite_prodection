from flask import Blueprint

bp = Blueprint('url_shortener', 
               __name__, 
               url_prefix='/s',  # Using '/s' for short, clean URLs
               template_folder='templates')

from . import routes