import traceback
from flask import request, render_template, redirect, url_for, session, Blueprint, flash, abort
from sqlalchemy import text
from app import db, login_manager, fernet, user_datastore
from app.models import User
from app.forms import LoginForm, RegisterForm, ChangePasswordForm
from uuid import uuid4
from flask_security import roles_required, roles_accepted, login_required, login_user, current_user, logout_user
import logging
from datetime import datetime

main = Blueprint('main', __name__)

@main.route('/')
def home():
    return render_template('home.html')

@main.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data.strip()).first() if form.username.data else None
        if user.check_password(form.password.data):
            regenerate_session()
            login_user(user)
            # print("successful login")
            # print("Is authenticated:", current_user.is_authenticated)
            return redirect(url_for('main.dashboard'))
        else:
            flash("Login credentials are invalid, please try again")
    elif request.method == "POST":
        flash("Validation Failed")
        for field, errors in form.errors.items():
            for i in errors:
                flash(f"{field} - {i}", category="warning")
    return render_template('login.html', form=form)


@main.route('/dashboard')
@login_required
@roles_accepted("user", "admin", "moderator")
def dashboard():
    # print([role.name for role in current_user.roles])
    return render_template('dashboard.html', username=current_user.username, bio=(fernet.decrypt(current_user.bio)).decode())

@main.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        user = user_datastore.create_user(username=form.username.data, password="placeholder", bio=fernet.encrypt((form.bio.data.encode())))
        user.hash_password(form.password.data)
        user_datastore.add_role_to_user(user, user_datastore.find_role("user"))
        # user.get_string()
        db.session.add(user)
        db.session.commit()
        flash("Registration Successful")
        return redirect(url_for("main.login"))
    elif request.method == "POST":
        flash("Validation Failed")
        for field, errors in form.errors.items():
            for i in errors:
                flash(f"{field} - {i}", category="warning")
    return render_template("register.html", form=form)

@main.route('/admin-panel')
@login_required
@roles_required("admin")
def admin():
    return render_template('admin.html')

@main.route('/moderator')
@login_required
@roles_required("moderator")
def moderator():
    return render_template('moderator.html')

@main.route('/user-dashboard')
@login_required
@roles_required("user")
def user_dashboard():
    return render_template('user_dashboard.html', username=current_user.username)


@main.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=current_user.username.strip()).first()
        user.hash_password(form.new_password.data)
        db.session.commit()
        flash('Password changed successfully', 'success')
        logout_user()
        return redirect(url_for('main.login'))
    elif request.method == "POST":
        flash("Validation Failed")
        for field, errors in form.errors.items():
            for i in errors:
                flash(f"{field} - {i}", category="warning")
    return render_template('change_password.html', form=form)

@main.route("/logout")
@login_required
def logout():
    session.clear()
    logout_user()
    return redirect(url_for("main.login"))

@main.route("/force400")
def force400():
    abort(400)

@main.route("/force500")
def force500():
    abort(500)

def regenerate_session():
    session.clear()
    session["csrf_token"] = uuid4().hex

def log_event(level, message, username=None):
    ip = request.remote_addr
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"{timestamp} Client IP: {ip}, User: {username or "N/A"} | {message}"
    if level == "info":
        logging.info(log_message)
    elif level == "warning":
        logging.warning(log_message)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))