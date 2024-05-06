from flask import Blueprint, render_template, url_for ,request,redirect
from flask_login import login_required, current_user, logout_user
from .models import User
main=Blueprint('main', __name__)

@main.route('/')
def index():
    # logout_user()
    return render_template('index.html')

@main.route('/profile', methods=['GET'])
@login_required
def profile():
    # Split the username by space and take the first part as the first name
    return render_template('profile.html',username=current_user.name, email=current_user.email)


@main.route('/admin')
@login_required
def admin():
    user = User.query.filter_by(email="admin@gmail.com").first()
    if current_user.name==user.name and current_user.password==user.password:
        return render_template('admin.html')
    else:
        return redirect(url_for('main.index'))


