from flask import Flask
from flask_sqlalchemy import SQLAlchemy 
from flask_mail import Mail
import os 
from flask_login import LoginManager
from dotenv import load_dotenv
load_dotenv()
mail=Mail()
db = SQLAlchemy()
import sys
from flask_cors import CORS



# print(os.environ.get("DATABASE_URI"))

# print(sys.executable)

app=Flask(__name__)
CORS(app)

def create_app():
    
    
    app.config['SECRET_KEY']='secret_key'
    app.config['SQLALCHEMY_DATABASE_URI']=os.environ.get("DATABASE_URI")

    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 465
    app.config['MAIL_USERNAME'] = os.environ.get("EMAIL")
    app.config['MAIL_PASSWORD'] = os.environ.get("EMAIL_PASSWORD")
    app.config['MAIL_DEFAULT_SENDER'] = os.environ.get("DEFAULT_SENDER")
    app.config['MAIL_USE_TLS'] = False
    app.config['MAIL_USE_SSL'] = True
    login_manager=LoginManager()
    login_manager.login_view= 'auth.login'
    login_manager.init_app(app)

    from .models import User

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))
    
    db.init_app(app)
    mail.init_app(app)

    from .crud_user import crud_user as crud_user_blueprint
    app.register_blueprint(crud_user_blueprint)

    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)
    
    from .tools import tools as tools_blueprint
    app.register_blueprint(tools_blueprint)
    

    
    
    
    return app
