from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_mail import Mail

db = SQLAlchemy()
login_manager = LoginManager()
mail = Mail() 

# Rate limiter setup (uses memory by default)
limiter = Limiter(key_func=get_remote_address)