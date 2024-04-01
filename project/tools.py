from flask import Blueprint, render_template, request, redirect, url_for, jsonify,flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_required, current_user
import os 
import hashlib
import re
import random
import string


tools=Blueprint('tools', __name__)




@tools.route('/password_strength', methods=['GET', 'POST'])
@login_required
def password_strength():
    error_message = None  # Initialize error message variable
    strongPassword= None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if len(password) < 8 or not checkCharacter(password) or not checkUppercase(password) or not checkUsername(password, username):
            error_message = "Password must be at least 8 characters long, contain at least one special character and one uppercase letter, and should not contain the username."
            strongPassword=generate_strong_password(username,password)
        else:
            error_message = "It's a strong password!"

    return render_template('password_strength.html', error_message=error_message,strongPassword=strongPassword)

def generate_strong_password(username, password):
    # Modify the password to make it strong
    modified_password = ''.join(random.choices(string.ascii_uppercase, k=1))  # Random uppercase letter
    modified_password += ''.join(random.choices(string.ascii_lowercase, k=1))  # Random lowercase letter
    modified_password += ''.join(random.choices(string.digits, k=1))  # Random digit
    modified_password += ''.join(random.choices(string.punctuation, k=1))  # Random special character
    modified_password += password  # Add the original password
    
    return modified_password

def checkCharacter(password):
    special_characters = ['!', '@', '#', '$', '%', ...]  # List of special characters
    for char in password:
        if char in special_characters:
            return True
    return False

def checkUppercase(password):
    for char in password:
        if char.isupper():
            return True
    return False

def checkUsername(password, username):
    if username.lower() not in password.lower():
        return True
    return False

def sha256_hash(text):
    return hashlib.sha256(text.encode()).hexdigest()

def md5_hash(text):
    return hashlib.md5(text.encode()).hexdigest()


@tools.route('/vulnerability_matcher', methods=['GET'])
@login_required
def vulnerability_matcher():
    # Handle the vulnerability matcher route logic here
    return render_template('vulnerability_matcher.html')


@tools.route('/cipher_conversion', methods=['GET', 'POST'])
@login_required
def cipher_conversion():
    # Handle the cipher conversion route logic here
    if request.method == 'POST':
        text = request.form.get('text')
        hash_choice = request.form.get('hash_choice')
        
        if text and hash_choice:
            if hash_choice == '1':
                hashed_text = sha256_hash(text)
                hash_type = "SHA256"
            elif hash_choice == '2':
                hashed_text = md5_hash(text)
                hash_type = "MD5"
            else:
                return "Invalid hash choice"
            flash( "Original:",text)
            return render_template('cipher_conversion.html', hashed_text=hashed_text, hash_type=hash_type)
        else:
            return "Text or hash choice missing"
            
    return render_template('cipher_conversion.html')

# You can add more routes for other tools as needed

# Example API endpoint

@tools.route('/ai_chatbot', methods=['GET','POST'])
@login_required
def ai_chatbot():
    if request.method=='POST':   
        pass
    return render_template('ai_chatbot.html')