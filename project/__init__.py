from flask import Flask
from flask_sqlalchemy import SQLAlchemy 

db = SQLAlchemy()


def create_app():
    
    app=Flask(__name__)
    
    app.config['SECRET_KEY']='secret_key'
    app.config['SQLALCHEMY_DATABASE_URI']='mysql://root:vicky2003@localhost/GuardianSecure'
    db.init_app(app)

    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)
    
    from .tools import tools as tools_blueprint
    app.register_blueprint(tools_blueprint)
    return app
