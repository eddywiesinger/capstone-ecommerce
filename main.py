import os
from datetime import datetime

import cloudinary
from flask import Flask, render_template, flash, redirect, url_for, request, jsonify
from flask_bootstrap import Bootstrap4
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

from config import BaseConfig
from decorators import admin_required

from cloudinary.uploader import upload
from cloudinary.utils import cloudinary_url

from uuid import uuid4

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

# CLOUDINARY
cloudinary.config(
    cloud_name=os.environ['CLOUDINARY_CLOUD_NAME'],
    api_key=os.environ['CLOUDINARY_API_KEY'],
    api_secret=os.environ['CLOUDINARY_API_SECRET'],
    secure=True
)


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


class Article(db.Model):
    __tablename__ = "articles"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), unique=True, nullable=False)
    price = db.Column(db.Float, nullable=False)
    cloudinary_public_id = db.Column(db.String(500))
    cloudinary_secure_url = db.Column(db.String(500))
    cloudinary_transformed_url = db.Column(db.String(500))
    description = db.Column(db.Text)
    created_on = db.Column(db.DateTime, nullable=False)


with application.app_context():
    db.create_all()


@application.route('/')
def home():
    return render_template('home.html', articles=Article.query.all())


@application.route('/users')
def users():
    flash('Users route under construction', 'danger')
    return redirect(url_for('home'))


@application.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        found_user = User.query.filter_by(email=email).first()
        if found_user:
            if check_password_hash(found_user.password, password):
                flash('Login successful.', 'success')
                login_user(found_user)
                return redirect(url_for('home'))
            else:
                flash('Login credentials invalid', 'danger')
                return redirect(url_for('login'))
        else:
            flash('This email is not registered', 'danger')
            return redirect(url_for('login'))
    else:
        return render_template('login.html')


@application.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@application.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        name = request.form.get('name')
        password = request.form.get('password')
        found_user = User.query.filter_by(email=email).first()
        if found_user:
            flash('E-Mail exists already', 'warning')
            return redirect(url_for('register'))

        hashed_pw = generate_password_hash(password)
        new_user = User(
            email=email,
            password=hashed_pw,
            name=name,
            needs_password_change=False,
            registered_on=datetime.now(),
            first_login=True,
            confirmed=False
        )

        db.session.add(new_user)
        db.session.commit()

        # login_user(user)

        flash('Registration successful! Please log in.', 'success')

        return redirect(url_for('login'))
    return render_template('register.html')


@application.route('/profile')
@login_required
def profile():
    flash('Profile route under construction', 'danger')
    return redirect(url_for('home'))


@application.route('/reset-password')
@login_required
def reset_password():
    flash('Reset password route under construction', 'danger')
    return redirect(url_for('home'))


@application.route('/checkout')
def checkout():
    flash('Checkout route under construction', 'danger')
    return redirect(url_for('home'))


@application.route('/new-article', methods=['GET', 'POST'])
@admin_required
def new_article():
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        price = request.form.get('price')
        image_file = request.files.get('image_file')
        found_article = Article.query.filter_by(name=name).first()
        if found_article:
            flash('Article name exists already', 'warning')
            return redirect(url_for('new_article'))

        new_public_id = ''
        secure_url = ''
        transformed_url = ''
        if image_file:
            upload_result = cloudinary.uploader.upload(image_file)
            application.logger.info(upload_result)
            if upload_result.get('public_id'):
                new_public_id = upload_result.get('public_id')
                secure_url = upload_result.get('secure_url')
                # TODO: Transform
                url, options = cloudinary_url(new_public_id, width=150, height=150, crop="fill")
                transformed_url = url
        new_article = Article(
            name=name,
            description=description,
            price=price,
            cloudinary_public_id=new_public_id,
            cloudinary_secure_url=secure_url,
            cloudinary_transformed_url=transformed_url,
            created_on=datetime.now()
        )

        db.session.add(new_article)
        db.session.commit()

        flash('Article was added successfully!', 'success')

        return redirect(url_for('home'))
    return render_template('admin/new_article.html')


if __name__ == '__main__':
    application.run(debug=True)
