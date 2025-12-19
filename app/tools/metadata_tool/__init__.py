from flask import Blueprint

bp = Blueprint('metadata_tool', 
               __name__, 
               url_prefix='/metadata-tool', 
               template_folder='templates')

from . import routes