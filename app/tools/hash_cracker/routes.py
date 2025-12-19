from flask import render_template, request, jsonify
from flask_login import login_required
import hashlib
import os
import time
from . import bp 

# Path to the wordlist, relative to this file's location
WORDLIST_DIR = os.path.join(os.path.dirname(__file__), 'wordlists')
DEFAULT_WORDLIST_PATH = os.path.join(WORDLIST_DIR, 'common_passwords.txt')

# --- Cracking Logic ---
def crack_hash(target_hash, wordlist_lines, hash_type='sha256'):
    target_hash = target_hash.lower().strip()
    start_time = time.time()
    max_processing_time = 15  # seconds 

    for i, word_bytes in enumerate(wordlist_lines):
        if time.time() - start_time > max_processing_time:
            return {"status": "timeout", "password": None, "attempts": i}

        try:
            word = word_bytes.decode('utf-8', errors='ignore').strip()
            hasher = hashlib.new(hash_type)
            hasher.update(word.encode('utf-8'))
            current_hash = hasher.hexdigest()

            if current_hash == target_hash:
                return {"status": "found", "password": word, "attempts": i + 1}
        except Exception:
            continue
            
    return {"status": "not_found", "password": None, "attempts": len(wordlist_lines)}

# --- Flask Routes ---

@bp.route('/')
@login_required
def index():
    return render_template('index_hash_cracker.html')

@bp.route('/crack', methods=['POST'])
@login_required
def crack_api():
    target_hash = request.form.get('targetHash', '').strip()
    hash_type = request.form.get('hashType', 'sha256').lower()
    wordlist_option = request.form.get('wordlistOption', 'default')
    
    if not target_hash:
        return jsonify({'error': 'Target hash is required.'}), 400
    if hash_type not in hashlib.algorithms_available:
        return jsonify({'error': f'Unsupported hash type: {hash_type}.'}), 400

    wordlist_lines = []
    try:
        if wordlist_option == 'upload':
            if 'wordlistFile' not in request.files or not request.files['wordlistFile'].filename:
                return jsonify({'error': 'Wordlist file is required.'}), 400
            file = request.files['wordlistFile']
            wordlist_lines = file.stream.readlines()
        elif wordlist_option == 'default':
            if os.path.exists(DEFAULT_WORDLIST_PATH):
                with open(DEFAULT_WORDLIST_PATH, 'rb') as f:
                    wordlist_lines = f.readlines()
            else:
                return jsonify({'error': 'Default wordlist not found on server.'}), 500
        else:
            return jsonify({'error': 'Invalid wordlist option.'}), 400

        if not wordlist_lines:
            return jsonify({'error': 'Wordlist is empty.'}), 400

    except Exception as e:
        return jsonify({'error': f'Error processing wordlist: {str(e)}'}), 500

    try:
        result = crack_hash(target_hash, wordlist_lines, hash_type)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': f'An unexpected server error occurred: {str(e)}', 'status': 'error'}), 500