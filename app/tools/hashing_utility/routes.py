from flask import render_template
from flask_login import login_required
from . import bp 

@bp.route('/')
@login_required # Added security
def index(): # Renamed to standard 'index'
    return render_template('hashing_index.html')