import string
import random
from flask import render_template, request, redirect, jsonify, current_app, url_for
from flask_login import login_required, current_user
from app.extensions import db
from app.models import User # Assuming models.py is in the app root
from sqlalchemy import text

from . import bp 

# Helper function to create a unique short code
def generate_short_code(length=6):
    chars = string.ascii_letters + string.digits
    while True:
        short_code = ''.join(random.choice(chars) for _ in range(length))
        # Check if the code already exists in the database
        with db.engine.connect() as connection:
            result = connection.execute(text("SELECT short_code FROM short_urls WHERE short_code = :code"), {'code': short_code}).first()
            if not result:
                return short_code

@bp.route('/')
@login_required
def index():
    return render_template('index_shortener.html')

@bp.route('/shorten', methods=['POST'])
@login_required
def shorten_url():
    long_url = request.json.get('long_url')
    if not long_url:
        return jsonify({'error': 'URL is required.'}), 400

    # Basic URL validation
    if not (long_url.startswith('http://') or long_url.startswith('https://')):
        return jsonify({'error': 'Invalid URL format. Must start with http:// or https://'}), 400
    
    short_code = generate_short_code()
    
    try:
        # Using SQLAlchemy Core for direct insert
        with db.engine.connect() as connection:
            connection.execute(text(
                "INSERT INTO short_urls (user_id, short_code, long_url) VALUES (:user_id, :code, :url)"
            ), {
                'user_id': current_user.id,
                'code': short_code,
                'url': long_url
            })
            connection.commit()

        short_url = url_for('url_shortener.redirect_to_url', short_code=short_code, _external=True)
        return jsonify({'short_url': short_url})

    except Exception as e:
        current_app.logger.error(f"Error creating short URL: {e}")
        return jsonify({'error': 'Could not create short URL.'}), 500


@bp.route('/<string:short_code>')
def redirect_to_url(short_code):
    with db.engine.connect() as connection:
        result = connection.execute(text("SELECT long_url FROM short_urls WHERE short_code = :code"), {'code': short_code}).first()
    
    if result:
        return redirect(result.long_url)
    else:
        return "URL not found", 404