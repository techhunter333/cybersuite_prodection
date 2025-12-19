from flask import (
    render_template, request, jsonify, abort, g, current_app
)
import os
import uuid
import sqlite3
from datetime import datetime, timezone, timedelta
from flask_login import login_required

# Import the blueprint
from . import bp 

# --- Database Configuration ---
DATABASE = 'pastes.db'

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(
            os.path.join(current_app.instance_path, DATABASE), 
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    # Correct path for v2 structure
    schema_path = os.path.join(os.path.dirname(__file__), 'schema.sql')
    try:
        with open(schema_path, 'r', encoding='utf-8') as f:
            db.executescript(f.read())
    except Exception as e:
        print(f"Error executing schema: {e}")
        raise

@bp.cli.command('init-db')
def init_db_command():
    try:
        if not os.path.exists(current_app.instance_path):
             os.makedirs(current_app.instance_path)
        init_db()
        print('Initialized the pastebin database.')
    except Exception as e:
        print(f"Error initializing database: {e}")

# --- Blueprint Routes ---

@bp.route('/')
@login_required # Only logged in users can create pastes
def index_pastebin():
    return render_template('pastebin_index.html')

@bp.route('/<uuid:paste_id>')
# NOTE: Removed login_required here so anyone with the link can view it (optional)
def view_paste_route(paste_id):
    return render_template('pastebin_view.html', paste_id=str(paste_id))


# --- API ROUTES ---

@bp.route('/api/create', methods=['POST'])
@login_required 
def api_create_paste():
    data = request.json
    if not data or 'encrypted_content' not in data:
        return jsonify({'error': 'No encrypted content provided.'}), 400

    encrypted_content = data['encrypted_content']
    expiration_key = data.get('expiration', '1_day') 
    
    paste_id = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc)
    expires_at = None

    expiration_mapping = {
        "never": None,
        "10_minutes": timedelta(minutes=10),
        "1_hour": timedelta(hours=1),
        "1_day": timedelta(days=1),
        "1_week": timedelta(days=7)
    }
    delta = expiration_mapping.get(expiration_key)
    if delta:
        expires_at = created_at + delta

    try:
        db = get_db()
        db.execute(
            "INSERT INTO pastes (id, encrypted_content, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (paste_id, encrypted_content, created_at, expires_at)
        )
        db.commit()
        return jsonify({'success': True, 'paste_id': paste_id})
    except sqlite3.Error as e:
        current_app.logger.error(f"Database error on paste creation: {e}")
        return jsonify({'error': 'Could not save paste.'}), 500

@bp.route('/api/get/<uuid:paste_id>', methods=['GET'])
def api_get_paste(paste_id):
    paste_id_str = str(paste_id)
    db = get_db()
    
    paste = db.execute(
        "SELECT encrypted_content, expires_at FROM pastes WHERE id = ?", (paste_id_str,)
    ).fetchone()

    if paste is None:
        return jsonify({'error': 'Paste not found.'}), 404

    if paste['expires_at']:
        expires_at_dt = paste['expires_at']
        if not expires_at_dt.tzinfo:
             expires_at_dt = expires_at_dt.replace(tzinfo=timezone.utc)

        if datetime.now(timezone.utc) > expires_at_dt:
            try:
                db.execute("DELETE FROM pastes WHERE id = ?", (paste_id_str,))
                db.commit()
            except sqlite3.Error as e:
                pass
            return jsonify({'error': 'Paste has expired.'}), 410

    return jsonify({'encrypted_content': paste['encrypted_content']})