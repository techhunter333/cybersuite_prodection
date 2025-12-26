from flask import Flask
from dotenv import load_dotenv
import os
from .extensions import db, login_manager, limiter, mail
from .models import User
from flask_dance.contrib.google import make_google_blueprint, google

def create_app():
    app = Flask(__name__)
    
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1' 
    os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'
    
    # Get the directory where THIS file (__init__.py) is located: app/
    basedir = os.path.abspath(os.path.dirname(__file__))
    # Go up one level to find the root folder (CyberToolkit_v2/)
    root_dir = os.path.dirname(basedir)
    # Point directly to .env
    dotenv_path = os.path.join(root_dir, '.env')
    
    if os.path.exists(dotenv_path):
        load_dotenv(dotenv_path)
        print(f"Loaded .env from: {dotenv_path}")
    else:
        print(f"WARNING: .env file not found at {dotenv_path}")
    # ------------------------------------------------------------

    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev_key')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # These should now be populated correctly
    app.config['VIRUSTOTAL_API_KEY'] = os.getenv('VIRUSTOTAL_API_KEY')
    app.config['ABUSEIPDB_API_KEY'] = os.getenv('ABUSEIPDB_API_KEY')
    
     # [NEW] Email Config
    app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
    app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT') or 587)
    app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS') == 'True'
    app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
    app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME') 
    
    # Debug print to verify
    print(f"DEBUG: VT Key Loaded? {'Yes' if app.config['VIRUSTOTAL_API_KEY'] else 'NO'}")
    print(f"DEBUG MAIL: Server={app.config['MAIL_SERVER']}, Port={app.config['MAIL_PORT']}")

    
    # Session Security (Prevents Cookie Hijacking)
    app.config['SESSION_COOKIE_HTTPONLY'] = True # Prevents JavaScript access to cookies (XSS protection)
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' # Prevents CSRF
    app.config['SESSION_COOKIE_SECURE'] = False  # Set to TRUE if you use HTTPS (Production)
    
    
    
    
    

    # Initialize Extensions
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = "Please log in to access this page."
    login_manager.login_message_category = "error"
    mail.init_app(app)
    
    # Initialize Rate Limiter
    limiter.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # Register Blueprints
    from .routes.auth import bp as auth_bp
    from .routes.main import bp as main_bp
    from .tools.cipher_tool import bp as cipher_tool_bp
    from .tools.cryptoguard import bp as cryptoguard_bp
    from .tools.password_strength import bp as password_strength_bp
    from .tools.password_generator import bp as password_generator_bp
    from .tools.encoder_decoder import bp as encoder_decoder_bp
    from .tools.steganography import bp as steganography_bp
    from .tools.pastebin import bp as pastebin_bp
    from .tools.redirect_checker import bp as redirect_checker_bp
    from .tools.threat_lookup import bp as threat_lookup_bp
    from .tools.threat_news import bp as threat_news_bp
    from .tools.file_encryptor import bp as file_encryptor_bp
    from .tools.digital_signature import bp as digital_signature_bp
    from .tools.hashing_utility import bp as hashing_utility_bp
    from .tools.hash_cracker import bp as hash_cracker_bp
    from .tools.qr_generator import bp as qr_generator_bp
    from .tools.url_shortener import bp as url_shortener_bp
    from .tools.file_share import bp as file_share_bp
    from .tools.subnet_calc import bp as subnet_bp
    from .tools.metadata_tool import bp as metadata_bp
    from .tools.whois_lookup import bp as whois_bp
    from .tools.sqli_scanner import bp as sqli_bp
    from .tools.jwt_debugger import bp as jwt_bp
    
    
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(cipher_tool_bp)
    app.register_blueprint(cryptoguard_bp)
    app.register_blueprint(password_strength_bp)
    app.register_blueprint(password_generator_bp)
    app.register_blueprint(encoder_decoder_bp)
    app.register_blueprint(steganography_bp)
    app.register_blueprint(pastebin_bp)
    app.register_blueprint(redirect_checker_bp)
    app.register_blueprint(threat_lookup_bp)
    app.register_blueprint(threat_news_bp)
    app.register_blueprint(file_encryptor_bp)
    app.register_blueprint(digital_signature_bp)
    app.register_blueprint(hashing_utility_bp)
    app.register_blueprint(hash_cracker_bp)
    app.register_blueprint(qr_generator_bp)
    app.register_blueprint(url_shortener_bp)
    app.register_blueprint(file_share_bp)
    app.register_blueprint(subnet_bp)
    app.register_blueprint(metadata_bp)
    app.register_blueprint(whois_bp)
    app.register_blueprint(sqli_bp)
    app.register_blueprint(jwt_bp)

    


    
    
    google_bp = make_google_blueprint(
        client_id=os.getenv("GOOGLE_OAUTH_CLIENT_ID"),
        client_secret=os.getenv("GOOGLE_OAUTH_CLIENT_SECRET"),
        # Use the full URL scopes to match what Google returns
        scope=[
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/userinfo.profile",
            "openid"
        ],
        redirect_url="/auth/google/authorized"
    )
    app.register_blueprint(google_bp, url_prefix="/auth/login") 
    
    
    
    
    
 # [TEMPORARY DATABASE SETUP ROUTE]
    @app.route('/setup-database')
    def setup_database():
        try:
            with app.app_context():
                db.create_all()
            return "Database Tables Created Successfully!"
        except Exception as e:
            return f"Error creating database: {str(e)}"

    
    
   
    
   
    


    return app