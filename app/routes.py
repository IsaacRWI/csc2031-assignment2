import traceback
from flask import request, render_template, redirect, url_for, session, Blueprint, flash, abort, current_app
from sqlalchemy import text
from app import db, login_manager, fernet, user_datastore
from app.models import User
from app.forms import LoginForm, RegisterForm, ChangePasswordForm
from uuid import uuid4
from flask_security import roles_required, roles_accepted, login_required, login_user, current_user, logout_user
from app.logger import log_event

main = Blueprint('main', __name__)

@main.route('/')
def home():
    return render_template('home.html')

@main.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data.strip()).first() if form.username.data else None
        if not user:  # if user is None ie no account matches that email
            form.username.errors.append("No account matching that email has been registered")
            lst = []
            flash("Validation Failed")
            for field, errors in form.errors.items():
                for i in errors:
                    val_error = f"{field} - {i}"
                    flash(val_error, category="warning")
                    lst.append(val_error)
            log_event("warning", f"Failed login attempted, validation error | {lst}", form.username.data)
            return render_template('login.html', form=form)
        if user.check_password(form.password.data):  # hashes input and compares it to stored password hash with bcrypt
            regenerate_session()
            login_user(user)
            log_event("info", "Successful login", current_user.username)
            # print("successful login")
            # print("Is authenticated:", current_user.is_authenticated)
            return redirect(url_for('main.dashboard'))
        else:
            log_event("warning", "Failed login attempted, incorrect password", user.username)
            flash("Login credentials are invalid, please try again")
    elif request.method == "POST":
        lst = []
        flash("Validation Failed")
        for field, errors in form.errors.items():
            for i in errors:
                val_error = f"{field} - {i}"
                flash(val_error, category="warning")
                lst.append(val_error)
        log_event("warning", f"Failed login attempted, validation error | {lst}", form.username.data)
    return render_template('login.html', form=form)


@main.route('/dashboard')
@login_required
@roles_accepted("user", "admin", "moderator")
def dashboard():
    # print([role.name for role in current_user.roles])
    log_event("info", "Shared dashboard accessed", current_user.username)
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
        log_event("info", "New user registered", user.username)
        return redirect(url_for("main.login"))
    elif request.method == "POST":
        flash("Validation Failed")
        lst = []
        for field, errors in form.errors.items():
            for i in errors:
                val_error = f"{field} - {i}"
                flash(val_error, category="warning")
                lst.append(val_error)
        log_event("warning", f"User registration failed, validation error | {lst}", form.username.data)
    return render_template("register.html", form=form)

@main.route('/admin-panel')
@login_required
@roles_required("admin")
def admin():
    log_event("info", "Admin dashboard accessed", current_user.username)
    return render_template('admin.html')

@main.route('/moderator')
@login_required
@roles_required("moderator")
def moderator():
    log_event("info", "Moderator dashboard accessed", current_user.username)
    return render_template('moderator.html')

@main.route('/user-dashboard')
@login_required
@roles_required("user")
def user_dashboard():
    log_event("info", "User dashboard accessed", current_user.username)
    return render_template('user_dashboard.html', username=current_user.username)


@main.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=current_user.username.strip()).first()
        user.hash_password(form.new_password.data)
        db.session.commit()
        log_event("info", "Password changed successfully", current_user.username)
        log_event("info", "Logged out user", current_user.username)
        session.clear()
        logout_user()
        flash('Password changed successfully', 'success')
        return redirect(url_for('main.login'))
    elif request.method == "POST":
        lst = []
        flash("Validation Failed")
        for field, errors in form.errors.items():
            for i in errors:
                val_error = f"{field} - {i}"
                flash(val_error, category="warning")
                lst.append(val_error)
        log_event("warning", f"Failed password change attempt, validation error | {lst}", current_user.username)
    return render_template('change_password.html', form=form)

@main.route("/logout")
@login_required
def logout():
    log_event("info", "Logged out user", current_user.username)
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

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))