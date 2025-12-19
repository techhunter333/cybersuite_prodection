import os
import uuid
from datetime import datetime, timedelta, timezone
from flask import render_template, request, jsonify, send_file, current_app
from flask_login import login_required
from app.extensions import db
from sqlalchemy import text
from . import bp 

# Folder to store encrypted files
UPLOAD_FOLDER = 'encrypted_uploads'

def get_upload_path():
    path = os.path.join(current_app.instance_path, UPLOAD_FOLDER)
    if not os.path.exists(path):
        os.makedirs(path)
    return path

@bp.route('/')
@login_required
def index():
    return render_template('index_share.html')

@bp.route('/download/<file_id>')
def download_page(file_id):
    # Public page to download (decryption happens in browser)
    return render_template('download_share.html', file_id=file_id)

# --- API ---

@bp.route('/api/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    original_name = request.form.get('filename') # Encrypted name or metadata
    
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    file_id = str(uuid.uuid4())
    secure_name = f"{file_id}.enc"
    save_path = os.path.join(get_upload_path(), secure_name)
    
    # Save the ENCRYPTED file to disk
    file.save(save_path)
    
    # Save metadata to DB
    expires_at = datetime.now(timezone.utc) + timedelta(days=1) # Auto-expire in 24h
    
    try:
        with db.engine.connect() as conn:
            conn.execute(text(
                "INSERT INTO encrypted_files (id, filename, filepath, expires_at) VALUES (:id, :name, :path, :exp)"
            ), {"id": file_id, "name": original_name, "path": secure_name, "exp": expires_at})
            conn.commit()
            
        return jsonify({'success': True, 'file_id': file_id})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/api/get-file/<file_id>')
def get_file_content(file_id):
    with db.engine.connect() as conn:
        result = conn.execute(text("SELECT * FROM encrypted_files WHERE id = :id"), {"id": file_id}).fetchone()
    
    if not result:
        return jsonify({'error': 'File not found or expired.'}), 404
        
    # Check expiration
    if result.expires_at and result.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        return jsonify({'error': 'File has expired.'}), 410

    # Serve the encrypted file
    file_path = os.path.join(get_upload_path(), result.filepath)
    return send_file(file_path, as_attachment=True, download_name=f"{result.filename}.enc")