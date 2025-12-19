from flask import Blueprint

bp = Blueprint('file_share', 
               __name__, 
               url_prefix='/file-share', 
               template_folder='templates',
               static_folder='static')

from . import routes