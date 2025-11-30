from app import db, bcrypt
from flask_login import UserMixin


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), default='user', nullable=False)
    bio = db.Column(db.String(500), nullable=False)

    def hash_password(self, text_password):
        """function to hash passwords through bcrypt"""
        self.password = bcrypt.generate_password_hash(text_password).decode("utf-8")

    def check_password(self, text_password):
        """function to compare the hashed output of a text password to the stored hash of account password"""
        return bcrypt.check_password_hash(self.password, text_password)

    def __init__(self, username, password, role, bio):
        self.username = username
        self.password = password
        self.role = role
        self.bio = bio







