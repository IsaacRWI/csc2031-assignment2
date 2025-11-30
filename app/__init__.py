from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from config import Config
from flask_wtf import CSRFProtect
from flask_bcrypt import Bcrypt
from flask_login import LoginManager

# initialize flask extensions for later use
db = SQLAlchemy()
csrf = CSRFProtect()
bcrypt = Bcrypt()
login_manager = LoginManager()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    csrf.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)

    login_manager.login_view = "main.login"
    login_manager.login_message_category = "info"

    from .routes import main
    app.register_blueprint(main)

    with app.app_context():
        from .models import User
        db.drop_all()
        db.create_all()
        # counter = 0

        users = [
            {"username": "user1@email.com", "password": "Userpass!23", "role": "user", "bio": "I'm a basic user"},
            {"username": "mod1@email.com", "password": "Modpass!23", "role": "moderator", "bio": "I'm a moderator"},
            {"username": "admin1@email.com", "password": "Adminpass!23", "role": "admin", "bio": "I'm an administrator"}
        ]

        for i in users:
            user = User(username=i["username"], password="placeholder", role=i["role"], bio=i["bio"])
            user.hash_password(i["password"])
            # user.get_string()
            db.session.add(user)
            db.session.commit()
            # counter += 1
    # print(counter)
    return app

