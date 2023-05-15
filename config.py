import os
from dotenv import load_dotenv

load_dotenv()


class BaseConfig(object):
    """Base configuration."""
    SECRET_KEY = os.environ['SECRET_KEY']
    SECURITY_PASSWORD_SALT = os.environ['SECURITY_PASSWORD_SALT']
    DEBUG = False
    BCRYPT_LOG_ROUNDS = 13
    WTF_CSRF_ENABLED = True
    DEBUG_TB_ENABLED = False
    DEBUG_TB_INTERCEPT_REDIRECTS = False
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_DATABASE_URI = 'sqlite:///ecommerce.db'

    # mail settings
    MAIL_SERVER = 'smtp.googlemail.com'
    MAIL_PORT = 465
    MAIL_USE_TLS = False
    MAIL_USE_SSL = True

    # gmail authentication
    MAIL_USERNAME = os.environ['MAIL_USERNAME']
    MAIL_PASSWORD = os.environ['MAIL_PASSWORD']

    # mail accounts
    MAIL_DEFAULT_SENDER = os.environ['MAIL_USERNAME']