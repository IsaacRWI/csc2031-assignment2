import traceback
from flask import request, render_template, redirect, url_for, session, Blueprint, flash, abort
from sqlalchemy import text
from app import db, login_manager, fernet
from app.models import User
from app.forms import LoginForm, RegisterForm, ChangePasswordForm
from uuid import uuid4
from flask_security import roles_required, roles_accepted, login_required, login_user, current_user, logout_user

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
    return render_template('login.html', form=form)


@main.route('/dashboard')
@roles_accepted("user", "admin", "moderator")
@login_required
def dashboard():
    # print([role.name for role in current_user.roles])
    return render_template('dashboard.html', username=current_user.username, bio=(fernet.decrypt(current_user.bio)).decode())

@main.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, password="placeholder", role="user",bio=fernet.encrypt(form.bio.data.encode()))
        user.hash_password(form.password.data)
        # user.get_string()
        db.session.add(user)
        db.session.commit()
        return redirect(url_for("main.login"))
    elif request.method == "POST":
        flash("Validation Failed")
        for field, errors in form.errors.items():
            for i in errors:
                flash(f"{field} - {i}", category="warning")
    return render_template("register.html", form=form)

@main.route('/admin-panel')
@login_required
def admin():
    if session.get('role') != 'admin':
        stack = ''.join(traceback.format_stack(limit=25))
        abort(403, description=f"Access denied.\n\n--- STACK (demo) ---\n{stack}")
    return render_template('admin.html')

@main.route('/moderator')
@login_required
def moderator():
    if session.get('role') != 'moderator':
        stack = ''.join(traceback.format_stack(limit=25))
        abort(403, description=f"Access denied.\n\n--- STACK (demo) ---\n{stack}")
    return render_template('moderator.html')

@main.route('/user-dashboard')
@login_required
def user_dashboard():
    if session.get('role') != 'user':
        stack = ''.join(traceback.format_stack(limit=25))
        abort(403, description=f"Access denied.\n\n--- STACK (demo) ---\n{stack}")
    return render_template('user_dashboard.html', username=session.get('user'))


@main.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=current_user.username.strip()).first()
        user.hash_password(form.new_password.data)
        db.session.commit()
        flash('Password changed successfully', 'success')
        return redirect(url_for('main.dashboard'))
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

def regenerate_session():
    session.clear()
    session["csrf_token"] = uuid4().hex

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))