from flask import Blueprint, render_template, request, redirect, url_for,flash,session
from werkzeug.security import generate_password_hash, check_password_hash
from .models import User
from . import db,mail
import random
from flask_mail import Message
from flask_login import login_user,logout_user,login_required, current_user

auth = Blueprint('auth', __name__)


@auth.route('/signup', methods=['POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('signupEmail')
        fullname = request.form.get('signupName')
        password = request.form.get('signupPassword')
        confirm_password = request.form.get('confirmPassword')
        security_question = request.form.get('securityQuestion')
        security_answer = request.form.get('securityAnswer')

        user = User.query.filter_by(email=email).first()
        if user:
            return redirect(url_for('auth.login'))

        if password != confirm_password:
            return redirect(url_for('auth.signup'))

        hashed_password = generate_password_hash(confirm_password)
        new_user = User(email=email, name=fullname, password=hashed_password, security_question=security_question, security_answer=security_answer)
        db.session.add(new_user)
        db.session.commit()
        return render_template('index.html', show_login=True)
    
    return render_template('index.html')

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
    return redirect(url_for('main.index'))


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
    
    return render_template('index.html')

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