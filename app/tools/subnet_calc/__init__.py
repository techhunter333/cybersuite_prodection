from flask import Blueprint

bp = Blueprint('subnet_calc', 
               __name__, 
               url_prefix='/subnet-calc', 
               template_folder='templates',
               static_folder='static')

from . import routes