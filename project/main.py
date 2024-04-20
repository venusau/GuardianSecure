from flask import Blueprint, render_template, url_for ,request,redirect
from flask_login import login_required, current_user, logout_user
main=Blueprint('main', __name__)

@main.route('/')
def index():
    logout_user()
    return render_template('index.html')

@main.route('/profile', methods=['GET'])
@login_required
def profile():
    # Split the username by space and take the first part as the first name
    return render_template('profile.html',username=current_user.name)

@main.route('/about')
def about_web_app():
    return render_template('about.html')