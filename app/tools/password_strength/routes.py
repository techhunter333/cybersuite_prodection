from flask import render_template
from flask_login import login_required # <-- ADDED IMPORT
from . import bp 

@bp.route('/')
@login_required # <-- ADDED SECURITY PROTECTION
def index(): # <-- Simplified function name to 'index'
    """
    Renders the main page for the password strength checker.
    """
    # [FIX] Render the correct, unified template name
    return render_template('pw_strength_index.html')