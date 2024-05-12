from . import app, db 
from flask import Flask, jsonify, request, Blueprint
from werkzeug.security import generate_password_hash
from .models import User
import os 
from flask_login import current_user, login_required
from dotenv import load_dotenv
load_dotenv()

crud_user=Blueprint("crud_user", __name__)

@app.route('/users', methods=["GET"])
@login_required
def get_user():
    user = User.query.filter_by(email=os.environ.get("ADMIN_EMAIL")).first()
    if current_user.name==user.name and current_user.password==user.password:
        users = User.query.all()
        json_users=list(map(lambda x: x.to_json(), users))
        return jsonify({"users":json_users}), 200,
    return jsonify({"message":"You are not authorized to see this information."}), 401,

@app.route('/update_user/<int:user_id>', methods=["PATCH"])
@login_required
def update_user(user_id):
    userAdmin = User.query.filter_by(email=os.environ.get("ADMIN_EMAIL")).first()
    if current_user.name==userAdmin.name and current_user.password==userAdmin.password:
        user = User.query.get(user_id)
        if not user:
            return jsonify({"message":"User not found."}), 404
        elif user.name==userAdmin.name and user.email==userAdmin.email:
            return jsonify({"message":"You can't update the admin account."}), 401,
        

        data=request.json
        user.id=data.get("id", user.id)
        user.name=data.get("name", user.name)
        user.email=data.get("email", user.email)
        try:
            db.session.commit()
        except Exception as e:
            return jsonify({"message":f"Something went wrong , ERROR:{str(e)}"}), 500,

        return jsonify({"message":"User updated successfully"}), 200,
    return jsonify({"message":"You are not authorized to see this information."}), 401,


@app.route('/delete_user/<int:user_id>', methods=["DELETE"])
def delete_user(user_id):
    userAdmin = User.query.filter_by(email=os.environ.get("ADMIN_EMAIL")).first()
    if current_user.name==userAdmin.name and current_user.password==userAdmin.password:
        user = User.query.get(user_id)
        if not user:
            return jsonify({"message":"User not found."}), 404
        elif user.name==userAdmin.name and user.email==userAdmin.email:
            return jsonify({"message":"You can't delete the admin account."}), 401,
        try:
            db.session.delete(user)
            db.session.commit()
        except Exception as e:
            return jsonify({"message":f"Something went wrong. ERROR{str(e)}"}), 500,

        return jsonify({"message":"User deleted successfully"}), 200,
    return jsonify({"message":"You are not authorized to see this information."}), 401,


