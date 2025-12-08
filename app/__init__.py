from flask import Flask, render_template
from flask_security import SQLAlchemyUserDatastore, Security
from flask_sqlalchemy import SQLAlchemy
from config import Config
from flask_wtf import CSRFProtect
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from cryptography.fernet import Fernet
import os
from dotenv import load_dotenv
import logging
from logging.handlers import RotatingFileHandler

# initializing Fernet to encrypt bio
load_dotenv()
FERNET_KEY = os.getenv("FERNET_KEY")
fernet = Fernet(FERNET_KEY)

# initialize flask extensions for later use
db = SQLAlchemy()
csrf = CSRFProtect()
bcrypt = Bcrypt()
login_manager = LoginManager()

user_datastore = SQLAlchemyUserDatastore(db, None, None)

def configure_logging(app):
    os.makedirs("logs", exist_ok=True)

    for i in app.logger.handlers[:]:
        app.logger.removeHandler(i)

    formatter = logging.Formatter("%(message)s")
    app.logger.setLevel(logging.DEBUG)


    if app.debug or app.config.get("ENV") == "development":
        log_file = "logs/debug.log"
        file_handler = RotatingFileHandler(log_file, maxBytes=5*1024*1024, backupCount=3)
        file_handler.setLevel(logging.DEBUG)
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG)
    else:
        log_file = "logs/production.log"
        file_handler = RotatingFileHandler(log_file, maxBytes=5*1024*1024, backupCount=3)
        file_handler.setLevel(logging.INFO)
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    app.logger.addHandler(file_handler)
    app.logger.addHandler(console_handler)


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    configure_logging(app)

    db.init_app(app)
    csrf.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)

    login_manager.login_view = "main.login"
    login_manager.login_message_category = "info"

    from .routes import main
    app.register_blueprint(main)

    with app.app_context():
        from .models import User, Role, roles_users
        user_datastore.user_model = User
        user_datastore.role_model = Role
        Security(app, user_datastore)

        db.drop_all()
        db.create_all()
        # counter = 0

        for i in ["user", "moderator", "admin"]:
            user_datastore.find_or_create_role(name=i)
            db.session.commit()


        users = [
            {"username": "user1@email.com", "password": "Userpass!23", "role": "user", "bio": "I'm a basic user"},
            {"username": "mod1@email.com", "password": "Modpass!23", "role": "moderator", "bio": "I'm a moderator"},
            {"username": "admin1@email.com", "password": "Adminpass!23", "role": "admin", "bio": "I'm an administrator"}
        ]

        for i in users:
            user = user_datastore.create_user(username=i["username"], password="placeholder", bio=fernet.encrypt((i["bio"]).encode()))
            user.hash_password(i["password"])
            user_datastore.add_role_to_user(user, user_datastore.find_role(i["role"]))
            # user.get_string()
            db.session.add(user)
            db.session.commit()
            # counter += 1
    # print(counter)

    @app.errorhandler(403)
    def forbidden(e):
        return render_template("403_forbidden.html"), 403

    @app.errorhandler(400)
    def bad_request(e):
        return render_template("400_bad_request.html"), 400

    @app.errorhandler(404)
    def not_found(e):
        return render_template("404_not_found.html"), 404

    @app.errorhandler(500)
    def internal_server_error(e):
        return render_template("500_internal_server_error.html"), 500
    return app

