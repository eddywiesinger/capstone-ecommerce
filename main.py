from flask import Flask, render_template, flash, redirect, url_for
from flask_bootstrap import Bootstrap4
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy

from config import BaseConfig

application = Flask(__name__, static_folder='static')
application.config.from_object(BaseConfig())

# BOOTSTRAP
Bootstrap4(application)

# LOGIN MANAGER
login_manager = LoginManager()
login_manager.init_app(application)
login_manager.login_view = "login"

# DB
db = SQLAlchemy(application)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


##CONFIGURE TABLES
class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    needs_password_change = db.Column(db.Boolean, nullable=False, default=True)
    registered_on = db.Column(db.DateTime, nullable=False)
    mfa_secret = db.Column(db.String(250))
    first_login = db.Column(db.Boolean, nullable=False)
    confirmed = db.Column(db.Boolean, nullable=False)
    confirmed_on = db.Column(db.DateTime, nullable=True)


@application.route('/')
def home():
    return render_template('home.html')


@application.route('/users')
def users():
    flash('Users route under construction', 'danger')
    return redirect(url_for('home'))


@application.route('/login')
def login():
    flash('Login route under construction', 'danger')
    return redirect(url_for('home'))


@application.route('/register')
def register():
    flash('Register route under construction', 'danger')
    return redirect(url_for('home'))


@application.route('/reset-password')
@login_required
def reset_password():
    flash('Reset password route under construction', 'danger')
    return redirect(url_for('home'))


if __name__ == '__main__':
    application.run(debug=True)
