from . import db

class User(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    name=db.Column(db.String(250))
    email=db.Column(db.String(100), unique=True)
    password=db.Column(db.String(500))
    security_question=db.Column(db.String(250))
    security_answer=db.Column(db.String(250))