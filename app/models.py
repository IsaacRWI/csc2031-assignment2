from app import db, bcrypt, user_datastore
from flask_login import UserMixin
from flask_security import RoleMixin
import uuid

roles_users = db.Table('roles_users',
    db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
    db.Column('role_id', db.Integer(), db.ForeignKey('role.id'))
)  # copied from geeks for geeks

class Role(db.Model, RoleMixin):
    __tablename__ = "role"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)

class User(db.Model, UserMixin):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    active = db.Column(db.Boolean(), default=True)  # required for flask security too or it gets mad
    fs_uniquifier = db.Column(db.String(255), unique=True, nullable=False, default=lambda: uuid.uuid4().hex)
    role = db.relationship("Role", secondary=roles_users, backref="roled", lazy="dynamic")
    bio = db.Column(db.String(500), nullable=False)

    def hash_password(self, text_password):
        """function to hash passwords through bcrypt"""
        self.password = bcrypt.generate_password_hash(text_password).decode("utf-8")

    def check_password(self, text_password):
        """function to compare the hashed output of a text password to the stored hash of account password"""
        return bcrypt.check_password_hash(self.password, text_password)

    def __init__(self, username, password, roles, bio, active, fs_uniquifier):
        self.username = username
        self.password = password
        self.roles = roles
        self.bio = bio
        self.active = active
        self.fs_uniquifier = fs_uniquifier

    def get_string(self):
        print(self.username)
        print(self.password)
        print(self.roles)
        print(self.bio)
        print("--------------------")







