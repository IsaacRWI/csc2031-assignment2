import traceback
from flask import request, render_template, redirect, url_for, session, Blueprint, flash, abort
from sqlalchemy import text
from app import db, login_manager, fernet
from app.models import User
from app.forms import LoginForm, RegisterForm
from flask_login import login_user, current_user, logout_user, login_required
from uuid import uuid4

main = Blueprint('main', __name__)

@main.route('/')
def home():
    return render_template('home.html')

@main.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first() if form.username.data else None
        if user.check_password(form.password.data):
            regenerate_session()
            login_user(user)
            # print("successful login")
            return redirect(url_for('main.dashboard'))
        else:
            flash("Login credentials are invalid, please try again")
    return render_template('login.html', form=form)


@main.route('/dashboard')
@login_required
def dashboard():
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
    # Require basic "login" state
    if 'user' not in session:
        stack = ''.join(traceback.format_stack(limit=25))
        abort(403, description=f"Access denied.\n\n--- STACK (demo) ---\n{stack}")

    username = session['user']

    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')

        user = db.session.execute(
            text(f"SELECT * FROM user WHERE username = '{username}' AND password = '{current_password}' LIMIT 1")
        ).mappings().first()

        # Enforce: current password must be valid for user
        if not user:
            flash('Current password is incorrect', 'error')
            return render_template('change_password.html')

        # Enforce: new password must be different from current password
        if new_password == current_password:
            flash('New password must be different from the current password', 'error')
            return render_template('change_password.html')

        db.session.execute(
            text(f"UPDATE user SET password = '{new_password}' WHERE username = '{username}'")
        )
        db.session.commit()

        flash('Password changed successfully', 'success')
        return redirect(url_for('main.dashboard'))

    return render_template('change_password.html')

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