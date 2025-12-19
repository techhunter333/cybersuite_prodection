from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required, current_user
from app.models import ActivityLog, Favorite
from app.extensions import db
bp = Blueprint('main', __name__)

@bp.route('/')
@login_required
def dashboard():
    return render_template('dashboard.html')

@bp.route('/activity')
@login_required
def activity():
    logs = ActivityLog.query.filter_by(user_id=current_user.id).order_by(ActivityLog.timestamp.desc()).limit(50).all()
    return render_template('activity.html', logs=logs)

# --- [THE FIX] ADD THESE TWO ROUTES ---
@bp.route('/privacy')
def privacy_policy():
    return render_template('privacy.html')

@bp.route('/terms')
def terms_of_service():
    return render_template('terms.html')


@bp.route('/api/toggle-favorite', methods=['POST'])
@login_required
def toggle_favorite():
    data = request.json
    endpoint = data.get('endpoint')
    name = data.get('name')
    
    existing = Favorite.query.filter_by(user_id=current_user.id, tool_endpoint=endpoint).first()
    
    if existing:
        db.session.delete(existing)
        action = "removed"
    else:
        new_fav = Favorite(user_id=current_user.id, tool_endpoint=endpoint, tool_name=name)
        db.session.add(new_fav)
        action = "added"
        
    db.session.commit()
    return jsonify({'status': 'success', 'action': action})

# Pass favorites to every template automatically
@bp.app_context_processor
def inject_favorites():
    if current_user.is_authenticated:
        # Import Favorite model inside the function to avoid circular import if needed
        from app.models import Favorite 
        favs = Favorite.query.filter_by(user_id=current_user.id).all()
        return dict(user_favorites=favs)
    return dict(user_favorites=[])