import os
from dotenv import load_dotenv
load_dotenv()
class Config:
    DEBUG = True
    SECRET_KEY = os.getenv("SECRET_KEY")
    SQLALCHEMY_DATABASE_URI = 'sqlite:///site.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

# config_test = Config()
# print(config_test.SECRET_KEY)