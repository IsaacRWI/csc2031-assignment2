import os
from dotenv import load_dotenv
load_dotenv()
class Config:

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SESSION_COOKIE_HTTP_ONLY = True
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SECURITY_PASSWORD_HASH = "plaintext"  # tells flask security too not to hash the password automatically so i can do it myself
    WTF_CSRF_ENABLED = True
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
    X_FRAME_OPTIONS = "DENY"
    X_CONTENT_TYPE_OPTIONS = "nosniff"

class DevelopmentConfig(Config):
    DEBUG = True
    SECRET_KEY = "DO NOT USE FOR PRODUCTION"
    SQLALCHEMY_DATABASE_URI = 'sqlite:///site.db'

class ProductionConfig(Config):
    DEBUG = False
    SECRET_KEY = os.getenv("SECRET_KEY")
    SQLALCHEMY_DATABASE_URI = os.getenv("DB_URI")



# config_test = Config()
# print(config_test.SECRET_KEY)