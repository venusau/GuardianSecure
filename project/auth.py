from __future__ import annotations

from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from .models import User
from . import db, mail
import os
from flask_mail import Message
from flask_login import login_user, logout_user, login_required, current_user

from libs.otp import generate_otp, store_otp, verify_otp, rate_limit_otp
from .oauth_setup import oauth

auth = Blueprint('auth', __name__)

OTP_SIGNUP = "signup"
OTP_RESET = "reset"


# ---------- OTP delivery ----------

def _send_email_otp(email: str, otp: str) -> bool:
    """Send OTP via email. Returns True if delivered (or dev-logged)."""
    if os.environ.get("DEV_LOG_OTP", "false").lower() == "true":
        print(f"[DEV OTP] {email} -> {otp}")
        flash(f"DEV MODE: your OTP is {otp}", "success")
        return True
    try:
        msg = Message("Your GuardianSecure verification code", recipients=[email])
        msg.body = f"Your one-time verification code is {otp}. It expires in 10 minutes."
        mail.send(msg)
        return True
    except Exception as e:
        print(f"[OTP send failed] {email}: {e}")
        flash("Could not send OTP email. Check mail configuration.", "error")
        return False


def _send_sms_otp(phone: str, otp: str) -> bool:
    """Best-effort SMS OTP via Twilio. Returns False if not configured."""
    sid = os.getenv("TWILIO_ACCOUNT_SID")
    token = os.getenv("TWILIO_AUTH_TOKEN")
    from_number = os.getenv("TWILIO_FROM_NUMBER")
    if not (sid and token and from_number):
        return False
    try:
        from twilio.rest import Client
        client = Client(sid, token)
        client.messages.create(
            body=f"Your GuardianSecure verification code is {otp}.",
            from_=from_number,
            to=phone,
        )
        return True
    except Exception as e:
        print(f"[SMS OTP failed] {phone}: {e}")
        return False


def _dispatch_otp(email: str, otp: str, phone: str | None = None) -> None:
    if _send_email_otp(email, otp):
        if phone:
            _send_sms_otp(phone, otp)


# ---------- Signup ----------

def password_strength(password, username):
    problems = []

    if not password or not username:
        problems.append("Password and username cannot be empty")

    if len(password) < 8:
        problems.append("Password must be at least 8 characters long")

    if not any(char.isupper() for char in password):
        problems.append("Password must contain at least one uppercase letter")

    if not any(char.islower() for char in password):
        problems.append("Password must contain at least one lowercase letter")

    if not any(char.isdigit() for char in password):
        problems.append("Password must contain at least one numeric digit")

    special_characters = "!@#$%^&*()-_=+[{]}|;:'\",<.>/?"
    if not any(char in special_characters for char in password):
        problems.append("Password must contain at least one special character")

    if username.lower() in password.lower():
        problems.append("Password cannot contain your username")

    return not problems, problems


@auth.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('signupEmail')
        fullname = request.form.get('signupName')
        password = request.form.get('signupPassword')
        confirm_password = request.form.get('confirmPassword')
        phone = request.form.get('signupPhone') or None

        if not password == confirm_password:
            flash('Both passwords do not match')
            return redirect(url_for('auth.signup'))

        valid, problems = password_strength(password, fullname)

        if User.query.filter_by(email=email).first():
            flash("User already exists")
            return redirect(url_for('auth.signup'))

        if not valid:
            for i in problems:
                flash(i)
            return render_template('signup.html')

        allowed, _ = rate_limit_otp(email, OTP_SIGNUP)
        if not allowed:
            flash("Too many attempts. Please wait a few minutes before requesting another code.")
            return render_template('signup.html')

        hashed_password = generate_password_hash(confirm_password, method="pbkdf2:sha256")
        session["email"] = email
        session["fullname"] = fullname
        session["hashed_password"] = hashed_password
        session["phone"] = phone
        otp = generate_otp()
        store_otp(email, OTP_SIGNUP, otp)
        _dispatch_otp(email, otp, phone)
        return redirect(url_for('auth.signup_confirmation'))

    return render_template('signup.html')


@auth.route('/signup_confirmation', methods=["GET", "POST"])
def signup_confirmation():
    if request.method == 'POST':
        email = session.get("email")
        fullname = session.get("fullname")
        hashed_password = session.get("hashed_password")
        phone = session.get("phone")
        otp = request.form.get("otp")

        if not email or not hashed_password:
            flash("Session expired. Please sign up again.")
            return redirect(url_for('auth.signup'))

        if not verify_otp(email, OTP_SIGNUP, otp or ""):
            flash("Wrong or expired OTP. Please try again!")
            return render_template("signup_confirmation.html")

        user = User(
            email=email,
            name=fullname,
            password=hashed_password,
            phone=phone,
            auth_provider="local",
            email_verified=True,
        )
        db.session.add(user)
        db.session.commit()
        session.pop("email", None)
        session.pop("fullname", None)
        session.pop("hashed_password", None)
        session.pop("phone", None)
        flash("You have been signed up successfully! You can log in now.")
        return redirect(url_for("auth.login"))

    return render_template("signup_confirmation.html")


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('loginEmail')
        password = request.form.get('loginPassword')
        remember = True if request.form.get('rememberMe') else False

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user, remember=remember)
            if user.role == "admin":
                return redirect(url_for('main.admin'))
            flash(f"Welcome, {user.name}")
            return redirect(url_for('main.profile'))
        elif not user:
            flash('User does not exist.\nPlease signup first.')
            return redirect(url_for('auth.signup'))
        else:
            flash('Wrong Password. You may change it in the forgot password section!')
            return redirect(url_for('auth.login'))
    return render_template('login.html')


# ---------- Password reset (email-OTP only, no security questions) ----------

@auth.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form.get('forgotEmail')
        user = User.query.filter_by(email=email).first()
        if not user:
            flash('Email not found.')
            return redirect(url_for('auth.reset_password'))

        allowed, _ = rate_limit_otp(email, OTP_RESET)
        if not allowed:
            flash("Too many reset attempts. Please wait a few minutes.")
            return redirect(url_for('auth.reset_password'))

        otp = generate_otp()
        store_otp(email, OTP_RESET, otp)
        _send_email_otp(email, otp)
        session['reset_email'] = email
        return redirect(url_for('auth.reset_password_code'))

    return render_template('reset_password.html')


@auth.route('/reset_password_code', methods=['GET', 'POST'])
def reset_password_code():
    if request.method == 'POST':
        email = session.get('reset_email')
        otp = request.form.get("otp")
        new_password = request.form.get('newPassword')
        confirm_new_password = request.form.get('confirmNewPassword')

        user = User.query.filter_by(email=email).first() if email else None
        if not user:
            flash("Session expired. Start the reset again.")
            return redirect(url_for('auth.reset_password'))

        if not verify_otp(email, OTP_RESET, otp or ""):
            flash("Wrong or expired OTP.")
            return render_template('reset_password_code.html')

        if new_password != confirm_new_password:
            flash('Passwords do not match.')
            return render_template('reset_password_code.html')

        valid, problems = password_strength(new_password, user.name or email)
        if not valid:
            for i in problems:
                flash(i)
            return render_template('reset_password_code.html')

        user.password = generate_password_hash(new_password, method="pbkdf2:sha256")
        db.session.commit()
        session.pop('reset_email', None)
        flash("Password updated. Please sign in.")
        return redirect(url_for('auth.login'))

    return render_template('reset_password_code.html')


# ---------- OAuth2 / OIDC SSO ----------

@auth.route('/login/<provider>')
def oauth_login(provider):
    client = oauth.create_client(provider)
    if not client:
        flash(f"{provider.title()} login is not configured.")
        return redirect(url_for('auth.login'))
    redirect_uri = url_for('auth.oauth_callback', provider=provider, _external=True)
    return client.authorize_redirect(redirect_uri, code_challenge_method='S256')


@auth.route('/callback/<provider>')
def oauth_callback(provider):
    client = oauth.create_client(provider)
    if not client:
        flash(f"{provider.title()} login is not configured.")
        return redirect(url_for('auth.login'))
    try:
        token = client.authorize_access_token()
    except Exception as e:
        print(f"[OAuth error] {provider}: {e}")
        flash("Authentication failed. Please try again.")
        return redirect(url_for('auth.login'))

    if provider == "github":
        profile = client.get('user').json()
        emails = client.get('user/emails').json()
        email = next(
            (e['email'] for e in emails if e.get('primary') and e.get('verified')),
            profile.get('email'),
        )
        sub = str(profile.get('id'))
        name = profile.get('name') or profile.get('login')
        picture = profile.get('avatar_url')
        email_verified = bool(email)
    else:
        userinfo = token.get('userinfo')
        if userinfo is None:
            userinfo = client.userinfo(token=token)
        email = userinfo.get('email')
        sub = userinfo.get('sub')
        name = userinfo.get('name') or email
        picture = userinfo.get('picture')
        email_verified = bool(userinfo.get('email_verified', False))

    if not email:
        flash("No email returned by the identity provider.")
        return redirect(url_for('auth.login'))

    user = User.query.filter_by(auth_provider=provider, provider_sub=sub).first()
    if not user:
        user = User.query.filter_by(email=email).first()
        if user and (user.auth_provider == "local" or not user.provider_sub):
            # Link an existing local account to this SSO identity.
            user.auth_provider = provider
            user.provider_sub = sub
            user.email_verified = email_verified or user.email_verified
            if not user.picture and picture:
                user.picture = picture
            db.session.commit()
        else:
            user = User(
                email=email,
                name=name,
                auth_provider=provider,
                provider_sub=sub,
                email_verified=email_verified,
                picture=picture,
                password=None,
                role="user",
            )
            db.session.add(user)
            db.session.commit()

    login_user(user)
    flash(f"Welcome, {user.name}")
    return redirect(url_for('main.profile'))


@auth.route('/wrong_credentials')
def wrong_credentials():
    problem = session.get('problem')
    print(problem)
    return render_template('wrong_credentials.html', problem=problem)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))
