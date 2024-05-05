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
        # if not password==confirm_password:
        #     problem='Both the password doesnot match '
        #     session['problem'] = problem
        #     return redirect(url_for('auth.wrong_credentials'))
        # if password_strength(password, fullname)==True:
        #     hashed_password = generate_password_hash(password, method='sha256')
        valid, problems = password_strength(password, fullname)
        
        user = User.query.filter_by(email=email).first()
        if valid:
            if user:
                return redirect(url_for('auth.login'))

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
            
            return redirect(url_for('main.profile'))
        elif not user:
            problem='User doesnot exist.'
            session['problem'] = problem
            return redirect(url_for('auth.wrong_credentials'))
        else:
            problem='Wrong Password.'
            session['problem'] = problem
            return redirect(url_for('auth.wrong_credentials'))
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
            flash('Email not found.', 'error')
            return redirect(url_for('auth.signup'))

        if user.security_question != security_question or user.security_answer != security_answer:
            flash('Wrong security question or answer.', 'error')
            problem='Wrong security question or answer.'
            session['problem'] = problem
            return redirect(url_for('auth.wrong_credentials'))

        if new_password != confirm_new_password:
            flash('Passwords do not match.', 'error')
            problem='Passwords do not match.'
            session['problem'] = problem
            return redirect(url_for('auth.wrong_credentials'))
        
        random_number = random.randint(100000, 999999)
        msg = Message("Subject", recipients=[email])
        msg.body = f"Your OTP is {random_number}"  # Use f-string to insert the OTP
        mail.send(msg)
        # Storing values in session
        session['email'] = email
        session['random_number'] = random_number
        session['confirm_new_password'] = confirm_new_password

        # Redirect to the page where the user will enter OTP
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
        user = User.query.filter_by(email=email).first()
       
        if user and user_random_otp == str(random_number):
            hashed_password = generate_password_hash(confirm_new_password)
            user.password=hashed_password
            db.session.commit()#this was the problem 
            return redirect(url_for('main.index'))
        else:
            problem="User doesn't exist or wrong otp "
            session['problem'] = problem
            return redirect(url_for('auth.wrong_credentials'))

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