import os
from dotenv import load_dotenv
load_dotenv()
class Config:
    DEBUG = True
    SECRET_KEY = os.getenv("SECRET_KEY")
    SQLALCHEMY_DATABASE_URI = 'sqlite:///site.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SESSION_COOKIE_HTTP_ONLY = True
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SECURITY_PASSWORD_HASH = "plaintext"  # tells flask security too not to hash the password automatically so i can do it myself

# config_test = Config()
# print(config_test.SECRET_KEY)