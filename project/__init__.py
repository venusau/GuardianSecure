import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail
from flask_login import LoginManager
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()

mail = Mail()
db = SQLAlchemy()
login_manager = LoginManager()


def create_app() -> Flask:
    app = Flask(__name__, static_folder="static", template_folder="templates")

    # ---- Core security / config ----
    secret = os.environ.get("SECRET_KEY")
    if not secret:
        # In production this must be set; dev fallback only.
        secret = "dev-only-insecure-change-me"
    app.config["SECRET_KEY"] = secret
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
        "DATABASE_URI", "sqlite:///guardian.db"
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # ---- Mail ----
    app.config["MAIL_SERVER"] = os.environ.get("MAIL_SERVER", "smtp.gmail.com")
    app.config["MAIL_PORT"] = int(os.environ.get("MAIL_PORT", "465"))
    app.config["MAIL_USERNAME"] = os.environ.get("EMAIL")
    app.config["MAIL_PASSWORD"] = os.environ.get("EMAIL_PASSWORD")
    app.config["MAIL_DEFAULT_SENDER"] = os.environ.get("DEFAULT_SENDER")
    app.config["MAIL_USE_TLS"] = os.environ.get("MAIL_USE_TLS", "False").lower() == "true"
    app.config["MAIL_USE_SSL"] = os.environ.get("MAIL_USE_SSL", "True").lower() == "true"

    CORS(app)
    login_manager.login_view = "auth.login"
    login_manager.init_app(app)

    from .models import User

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    db.init_app(app)
    mail.init_app(app)

    # ---- OAuth2 / OIDC SSO (registers providers present in env) ----
    from .oauth_setup import init_oauth
    init_oauth(app)

    # ---- Blueprints ----
    from .crud_user import crud_user
    from .main import main
    from .auth import auth
    from .tools import tools
    from .api import api

    app.register_blueprint(crud_user)
    app.register_blueprint(main)
    app.register_blueprint(auth)
    app.register_blueprint(tools)
    app.register_blueprint(api)

    return app
