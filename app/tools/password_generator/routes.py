from flask import render_template
from flask_login import login_required
from . import bp 

# [CLEANUP] Removed the standalone 'app = Flask(...)' instance

@bp.route('/')
@login_required # ADDED SECURITY PROTECTION
def index(): # Simplified function name
    """Renders the main page for the secure password generator."""
    # [FIX] Render the correct, unified template name
    return render_template('pw_generator_index.html')