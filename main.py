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

import stripe

# TODO: Delete Product Route missing
# https://stripe.com/docs/api/products/delete

stripe.api_key = os.environ['STRIPE_SECRET_KEY']
YOUR_DOMAIN = 'http://localhost:5000'

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


# class Article(db.Model):
#     __tablename__ = "articles"
#     id = db.Column(db.Integer, primary_key=True)
#     name = db.Column(db.String(250), unique=True, nullable=False)
#     price = db.Column(db.Float, nullable=False)
#     cloudinary_public_id = db.Column(db.String(500))
#     cloudinary_secure_url = db.Column(db.String(500))
#     cloudinary_transformed_url = db.Column(db.String(500))
#     description = db.Column(db.Text)
#     created_on = db.Column(db.DateTime, nullable=False)


with application.app_context():
    db.create_all()


@application.route('/')
def home():
    all_products = stripe.Product.list()
    for product in all_products:
        if product.default_price:
            price = stripe.Price.retrieve(product.default_price)
            product.price_amount = price.unit_amount_decimal
    return render_template('home.html', articles=all_products)  # Article.query.all()


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


@application.route('/article/new', methods=['GET', 'POST'])
@admin_required
def new_article():
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        price = request.form.get('price')
        image_file = request.files.get('image_file')
        url = ''
        if image_file:
            file_obj = stripe.File.create(
                file=image_file,
                purpose='dispute_evidence',
            )
            url = file_obj.url
        stripe.Product.create(
            name=name,
            description=description,
            default_price_data={
                'currency': 'EUR',
                'unit_amount_decimal': price
            },
            images=[url]
        )

        flash('Article was added successfully!', 'success')

        return redirect(url_for('home'))
    return render_template('admin/new_article.html')


@application.route('/articles')
@admin_required
def articles():
    all_products = stripe.Product.list()
    for product in all_products:
        if product.default_price:
            price = stripe.Price.retrieve(product.default_price)
            product.price_amount = price.unit_amount_decimal
    return render_template('admin/articles.html', articles=all_products)  # Article.query.all()


@application.route('/article/<article_id>', methods=['GET', 'POST'])
@admin_required
def edit_article(article_id):
    article_to_edit = stripe.Product.retrieve(article_id)  # Article.query.get(int(article_id))
    current_price = stripe.Price.retrieve(article_to_edit.default_price)
    article_to_edit.price_amount = current_price.unit_amount_decimal
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        price = request.form.get('price')
        image_file = request.files.get('image_file')

        if name:
            stripe.Product.modify(
                article_id,
                name=name)
        if description:
            stripe.Product.modify(
                article_id,
                description=description
            )
        if price:
            deactivate_old_price = False
            if article_to_edit.default_price:
                deactivate_old_price = True
            created_price = stripe.Price.create(
                product=article_id,
                currency='EUR',
                unit_amount_decimal=price
            )
            stripe.Product.modify(
                article_id,
                default_price=created_price
            )
            if deactivate_old_price:
                stripe.Price.modify(
                    article_to_edit.default_price,
                    active=False
                )
        if image_file:
            url = ''
            if image_file:
                file_obj = stripe.File.create(
                    file=image_file,
                    purpose='dispute_evidence',
                    file_link_data={
                        'create': True
                    }
                )
                url = file_obj.links.data[0].url
                stripe.Product.modify(
                    article_id,
                    images=[url]
                )

        flash('Article was updated successfully!', 'success')

        return redirect(url_for('home'))
    return render_template('admin/edit_article.html', article=article_to_edit)


@application.route('/article/delete/<article_id>')
@admin_required
def delete_article(article_id):
    stripe.Product.delete(article_id)

    flash('Article was deleted successfully!', 'success')
    return redirect(url_for('home'))


@application.route('/unauthorized')
@login_required
def unauthorized():
    return render_template('error/unauthorized.html')


@application.route('/users')
@admin_required
def users():
    return render_template('admin/users.html', users=User.query.all())


@application.route('/checkout', methods=['GET', 'POST'])
def checkout():
    if request.method == 'POST':
        try:
            checkout_session = stripe.checkout.Session.create(
                line_items=[
                    {
                        # Provide the exact Price ID (for example, pr_1234) of the product you want to sell
                        'price': 'price_1N9oW6BXXPZuK6COQbRpcUei',
                        'quantity': 1,
                    },
                ],
                mode='payment',
                success_url=YOUR_DOMAIN + '/success.html',  # url_for('home'),
                cancel_url=YOUR_DOMAIN + '/cancel.html',  # url_for('checkout'),
            )
        except Exception as e:
            return str(e)

        return redirect(checkout_session.url, code=303)
    return render_template('checkout.html')


if __name__ == '__main__':
    application.run(debug=True)
