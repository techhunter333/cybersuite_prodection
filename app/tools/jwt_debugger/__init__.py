from flask import Blueprint

bp = Blueprint('jwt_debugger', 
               __name__, 
               url_prefix='/jwt-debugger', 
               template_folder='templates')

from . import routes