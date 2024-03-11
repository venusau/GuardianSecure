from flask import Blueprint, render_template, request, redirect, url_for, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from .models import User
from . import db 

auth = Blueprint('auth', __name__)

@auth.route('/signup', methods=['POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('signupEmail')
        fullname = request.form.get('signupName')
        password = request.form.get('signupPassword')
        confirm_password = request.form.get('confirmPassword')
        security_question = request.form.get('securityQuestion')  # Get the security question from the form
        security_answer = request.form.get('securityAnswer')  # Get the security answer from the form

        # Check if the user already exists
        user = User.query.filter_by(email=email).first()
        if user:
            # Redirect to login page if user already exists
            return redirect(url_for('auth.login'))

        # Check if passwords match
        if password != confirm_password:
            # Redirect or show error message
            return redirect(url_for('auth.signup'))

        # Create a new user with hashed password
        hashed_password = generate_password_hash(confirm_password)
        new_user = User(email=email, name=fullname, password=hashed_password, security_question=security_question, security_answer=security_answer)
        db.session.add(new_user)
        db.session.commit()

        # Redirect to login page after successful signup
        return redirect(url_for('auth.login'))
    
@auth.route('/', methods=['POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('loginEmail')  # Changed from 'username' to 'email'
        password = request.form.get('loginPassword')

        # Check if the user exists and password matches
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            # Redirect to profile page or return success message
            return redirect(url_for('main.profile'))  # Change the route to the profile page
        else:
            # Return error message or redirect to login page
            return redirect(url_for('auth.signup'))  # Redirect to login page if login fails


@auth.route('/reset_password', methods=['POST'])
def reset_password():#email sending and checking the code--> it should be done here 
    if request.method == 'POST':
        email = request.form.get('forgotEmail')
        security_question = request.form.get('forgotSecurityQuestion')
        security_answer = request.form.get('forgotSecurityAnswer')
        new_password = request.form.get('newPassword')
        confirm_new_password = request.form.get('confirmNewPassword')

        # Check if the user exists
        user = User.query.filter_by(email=email).first()
        if not user:
            # Redirect or show error message
            return redirect(url_for('auth.reset_password'))

        # Verify security question and answer
        if user.security_question != security_question or user.security_answer != security_answer:
            # Redirect or show error message
            return redirect(url_for('auth.reset_password'))

        # Check if passwords match
        if new_password != confirm_new_password:
            # Redirect or show error message
            return redirect(url_for('auth.reset_password'))

        # Update user's password
        user.password = generate_password_hash(confirm_new_password)
        db.session.commit()

        # Redirect to login page after password reset
        return redirect(url_for('auth.login'))


@auth.route('/logout')
def logout():
    return "This is for logout"
