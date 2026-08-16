from . import db
from flask import jsonify, request, Blueprint
from .models import User
from flask_login import current_user, login_required
from dotenv import load_dotenv

load_dotenv()

crud_user = Blueprint("crud_user", __name__)


def _is_admin():
    return current_user.is_authenticated and current_user.role == "admin"


@crud_user.route('/users', methods=["GET"])
@login_required
def get_user():
    if _is_admin():
        users = User.query.all()
        json_users = [u.to_json() for u in users]
        return jsonify({"users": json_users}), 200
    return jsonify({"message": "You are not authorized to see this information."}), 401


@crud_user.route('/update_user/<int:user_id>', methods=["PATCH"])
@login_required
def update_user(user_id):
    if not _is_admin():
        return jsonify({"message": "You are not authorized to see this information."}), 401
    user = User.query.get(user_id)
    if not user:
        return jsonify({"message": "User not found."}), 404
    if user.role == "admin":
        return jsonify({"message": "You can't update the admin account."}), 401

    data = request.get_json(silent=True) or {}
    user.name = data.get("name", user.name)
    user.email = data.get("email", user.email)
    try:
        db.session.commit()
    except Exception as e:
        return jsonify({"message": f"Something went wrong, ERROR: {str(e)}"}), 500
    return jsonify({"message": "User updated successfully"}), 200


@crud_user.route('/delete_user/<int:user_id>', methods=["DELETE"])
@login_required
def delete_user(user_id):
    if not _is_admin():
        return jsonify({"message": "You are not authorized to see this information."}), 401
    user = User.query.get(user_id)
    if not user:
        return jsonify({"message": "User not found."}), 404
    if user.role == "admin":
        return jsonify({"message": "You can't delete the admin account."}), 401
    try:
        db.session.delete(user)
        db.session.commit()
    except Exception as e:
        return jsonify({"message": f"Something went wrong. ERROR {str(e)}"}), 500
    return jsonify({"message": "User deleted successfully"}), 200
