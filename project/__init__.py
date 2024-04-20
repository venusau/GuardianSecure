from flask import Flask
from flask_sqlalchemy import SQLAlchemy 
from flask_mail import Mail
import os 
from flask_login import LoginManager
mail=Mail()
db = SQLAlchemy()
import sys
print(sys.executable)


def create_app():
    
    app=Flask(__name__)
    
    app.config['SECRET_KEY']='secret_key'
    app.config['SQLALCHEMY_DATABASE_URI']='mysql://root:vicky2003@localhost/GuardianSecure'

    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 465
    app.config['MAIL_USERNAME'] = 'guardainsecurefoundation@gmail.com'
    app.config['MAIL_PASSWORD'] = 'kkhwblkaellpcleg'
    app.config['MAIL_DEFAULT_SENDER'] = 'guardainsecurefoundation@gmail.com'
    app.config['MAIL_USE_TLS'] = False
    app.config['MAIL_USE_SSL'] = True
    # kkhw blka ellp cleg
    login_manager=LoginManager()
    login_manager.login_view= 'auth.login'
    login_manager.init_app(app)

    from .models import User

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))
    
    db.init_app(app)
    mail.init_app(app)

    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)
    
    from .tools import tools as tools_blueprint
    app.register_blueprint(tools_blueprint)
    return app
