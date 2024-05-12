from flask import Blueprint, render_template, request, redirect, url_for,flash,session
from werkzeug.security import generate_password_hash, check_password_hash
from .models import User
from . import db,mail
import random
from flask_mail import Message
from flask_login import login_user,logout_user,login_required, current_user

auth = Blueprint('auth', __name__)


def password_strength(password, username):
    problems = []

    # Check if password and username are not empty
    if not password or not username:
        problems.append("Password and username cannot be empty")
    
    # Check if password is at least 8 characters long
    if len(password) < 8:
        problems.append("Password must be at least 8 characters long")
    
    # Check if password contains at least one uppercase letter
    if not any(char.isupper() for char in password):
        problems.append("Password must contain at least one uppercase letter")
    
    # Check if password contains at least one lowercase letter
    if not any(char.islower() for char in password):
        problems.append("Password must contain at least one lowercase letter")
    
    # Check if password contains at least one numeric digit
    if not any(char.isdigit() for char in password):
        problems.append("Password must contain at least one numeric digit")
    
    # Check if password contains at least one special character
    special_characters = "!@#$%^&*()-_=+[{]}\|;:'\",<.>/?"
    if not any(char in special_characters for char in password):
        problems.append("Password must contain at least one special character")

    # Check if password contains username (case insensitive)
    if username.lower() in password.lower():
        problems.append("Password cannot contain your username")
    
    # Return True if no problems encountered, else return list of problems
    return not problems, problems

@auth.route('/signup', methods=['GET','POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('signupEmail')
        fullname = request.form.get('signupName')
        password = request.form.get('signupPassword')
        confirm_password = request.form.get('confirmPassword')
        security_question = request.form.get('securityQuestion')
        security_answer = request.form.get('securityAnswer')

        if not password==confirm_password:
            problem='Both the password doesnot match '
            flash(problem)
            return redirect(url_for('auth.signup'))
        
        valid, problems = password_strength(password, fullname)
        
        user = User.query.filter_by(email=email).first()
        if valid:
            if user:
                flash("User already exist")
                return redirect(url_for('auth.signup'))

            hashed_password = generate_password_hash(confirm_password)
            new_user = User(email=email, name=fullname, password=hashed_password, security_question=security_question, security_answer=security_answer)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('auth.login'))
        else:
            for i in problems:
                flash(i)
    return render_template('signup.html')

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('loginEmail')
        password = request.form.get('loginPassword')
        remember= True if request.form.get('rememberMe') else False

        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user, remember=remember)
            useradmin = User.query.filter_by(email="admin@gmail.com").first()
            
            if current_user.name=='Admin' and current_user.password==useradmin.password:
                
                return redirect(url_for('main.admin'))
            flash(f"Welcome, {user.name}")
            return redirect(url_for('main.profile'))
        elif not user:
            flash('User doesnot exist.\nPlease signup first.')
            return redirect(url_for('auth.signup'))
        else:
            flash('Wrong Password. You may change the change in the forget password section!')
            return redirect(url_for('auth.login'))
    return render_template('login.html')


@auth.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form.get('forgotEmail')
        security_question = request.form.get('forgotSecurityQuestion')
        security_answer = request.form.get('forgotSecurityAnswer')
        new_password = request.form.get('newPassword')
        confirm_new_password = request.form.get('confirmNewPassword')

        user = User.query.filter_by(email=email).first()
        if not user:
            flash('Email not found.')
            return redirect(url_for('auth.signup'))
        print (user.email, user.security_question, user.security_answer)
        print(security_question, user.security_answer == security_answer )
        if not  user.security_question == security_question or not user.security_answer == security_answer:
            flash('Wrong security question or answer. Please enetr correct Security Question and Secuirty Answer')
            return redirect(url_for('auth.reset_password'))

        if new_password != confirm_new_password:
            flash('Passwords do not match.')
            return redirect(url_for('auth.reset_password'))
        
        name=user.name
        valid, problems = password_strength(confirm_new_password, name)
        if not valid:
            for i in problems:
                flash(i)
            return redirect(url_for('auth.reset_password'))
        
        random_number = random.randint(100000, 999999)
        msg = Message("Subject", recipients=[email])
        msg.body = f"Your OTP is {random_number}" 
        mail.send(msg)
        # Storing values in session
        session['email'] = email
        session['random_number'] = random_number
        session['confirm_new_password'] = confirm_new_password

        return redirect(url_for('auth.reset_password_code'))
    
    return render_template('reset_password.html')

@auth.route('/reset_password_code', methods=['GET', 'POST'])
def reset_password_code():
    if request.method == 'POST':
                # Retrieving values from session
        email = session.get('email')
        random_number = session.get('random_number')
        confirm_new_password = session.get('confirm_new_password')
        
        
        user_random_otp = request.form.get("otp")
        print(confirm_new_password)
        print(type(confirm_new_password))
        print()
        user = User.query.filter_by(email=email).first()
        
        if user and user_random_otp == str(random_number):
            hashed_password = generate_password_hash(confirm_new_password)
            user.password=hashed_password
            db.session.commit()#this was the problem 
            return redirect(url_for('auth.login'))
        elif not user :
            problem="User doesn't exist "
            flash(problem)
            return redirect(url_for('auth.reset_password'))
        else:
            problem="Wrong OTP"
            flash(problem)
            return redirect(url_for('auth.reset_password_code'))

    return render_template('reset_password_code.html')

@auth.route('/wrong_credentials')
def wrong_credentials():
    problem = session.get('problem')
    print(problem)
    return render_template('wrong_credentials.html',problem=problem)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))