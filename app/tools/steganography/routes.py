from flask import render_template
from flask_login import login_required
from . import bp 

@bp.route('/')
@login_required # Added security
def index(): # Simplified function name
    # [FIX] Render the new template name
    return render_template('steganography_index.html')