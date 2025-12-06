from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, EqualTo, Length, ValidationError, Email
import re
from bleach import clean
from app.models import User

common_passwords = {"Password123$", "Qwerty123!", "Adminadmin1@", "weLcome123!", "CustomPassword1234!", "loGinPasssWORD13213$"}
safe_tags = {"b", "i", "u", "em", "strong", 'a', 'p', 'ul', 'ol', 'li', 'br'}
safe_attributes = {"a":["href", "title"]}

class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    confirm_password = PasswordField("Confirm password", validators=[DataRequired(), EqualTo("password", message="Must match original password")])
    bio = TextAreaField("Enter something about yourself")
    submit = SubmitField("Register")

    def validate_username(self, username):
        username = username.data
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            raise ValidationError("Username already exists in database")

    def validate_password(self, password):
        password = password.data
        username = self.username.data.lower()
        if password in common_passwords:
            raise ValidationError("Password cannot be in blacklist")
        if username in password:
            raise ValidationError("Password cannot contain your username")
        if len(password) < 10:
            raise ValidationError("Password cannot be shorter than 10 characters")
        if not re.search(r"[A-Z]", password):
            raise ValidationError("Password must contain a capital letter")
        if not re.search(r"\d", password):
            raise ValidationError("Password must contain a number")
        if not re.search(r"[!@#$%^&*()_+={}|:;',.?/~]", password):
            raise ValidationError("Password must contain a special character")

    def validate_bio(self, bio):
        bio_content = bio.data
        sanitized_content = clean(bio_content, tags=safe_tags, attributes=safe_attributes, strip=True)
        if bio_content != sanitized_content:
            raise ValidationError("Bio contained restricted tags")

