from flask import Blueprint, render_template, request, redirect, url_for, jsonify,flash,current_app
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_required, current_user
import os 
import hashlib
import re
import random
import string
from dotenv import load_dotenv
from . import mail
from flask_mail import Message
import time
from zapv2 import ZAPv2
import requests
import json

load_dotenv()
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


@tools.route('/vulnerability_matcher', methods=['GET', 'POST'])
@login_required
def vulnerability_matcher():
    if request.method == 'POST':
        target = request.form.get('targetURL')  # Corrected variable name
        apiKey = os.environ.get("ZAP_API_KEY")# TODO: THIS HAS TO BE CHANGEDCHANGED
        k = 2 if request.form.get('options') == "Active Scan" else 1

        
        # ZAP is listening on port 8081
        zap = ZAPv2(apikey=apiKey, proxies={'http': 'http://127.0.0.1:8081', 'https': 'http://127.0.0.1:8081'})

        print('Spidering target {}'.format(target))

        # The scan returns a scan id to support concurrent scanning
        scanID = zap.spider.scan(target)

        while int(zap.spider.status(scanID)) < 100:
            # Poll the status until it completes
            print('Spider progress %: {}'.format(zap.spider.status(scanID)))
            time.sleep(1)

        print('Spider has completed!')

        # Prints the URLs the spider has crawled
        print('\n'.join(map(str, zap.spider.results(scanID))))

        # If required post process the spider results
        # TODO: Explore the Application more with Ajax Spider or Start scanning the application for vulnerabilities

        print("Enter 1 for Passive scan and 2 for Active scan \n")
        print("Warning: Active Scan takes much more time, Don't interrupt, it may affect the report")

        if int(k) == 2:
            print(f'Active Scanning target {target}')
            scanID = zap.ascan.scan(url=target)
            print(type(scanID))
            print(scanID)
            k=int(zap.ascan.status(scanID))
            while int(zap.ascan.status(scanID)) < 100:
                k=int(zap.ascan.status(scanID))
                if not k == int(zap.ascan.status(scanID)):
                    print('Scan progress %: {}'.format(zap.ascan.status(scanID)))
                    k=int(zap.ascan.status(scanID))
                # else:
                    # time.sleep(5)
            # Loop until the scanner has finished

        elif k == '1':
            while int(zap.pscan.records_to_scan) > 0:
                print('Records to passive scan : ' + zap.pscan.records_to_scan)
                time.sleep(2)
            # Loop until the passive scan has finished

            print('Passive Scan completed')

            # Print Passive scan results/alerts
            print('Hosts: {}'.format(', '.join(zap.core.hosts)))
            print('Alerts: ')
            print(zap.core.alerts())

        # Get JSON Report
        headers = {
            'Accept': 'application/json',
            'X-ZAP-API-Key': apiKey
        }

        generateFile = requests.get('http://localhost:8081/JSON/reports/action/generate/', params={
            'title': 'Report',
            'template': 'traditional-pdf',
            'sites': target,
            'reportFileName': 'Report',
            'reportDir': 'D:/GuardianSecure/project/'
        }, headers=headers)
        
        # Assuming the report is saved as "Report.pdf"
        # Attach the report to the email
        if generateFile.status_code == 200:
            user_email=current_user.email
            msg = Message('Your report of the vulnerability scan is attached', recipients=[user_email])
            msg.body = 'Please find the attached report.'
            with open("D:/GuardianSecure/project/Report.pdf", "rb") as fp: #TODO : HAS TO BE CORRECTED 
                msg.attach("Report.pdf", "application/pdf", fp.read())
            mail.send(msg)
            flash("Your report has been sent to your email. Please check your mail for the report")

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