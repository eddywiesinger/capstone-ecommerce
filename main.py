import os
from datetime import datetime

from flask import Flask, render_template, flash, redirect, url_for, request, jsonify
from flask_bootstrap import Bootstrap4
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship
from werkzeug.security import check_password_hash, generate_password_hash

from config import BaseConfig
from decorators import admin_required

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


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


##CONFIGURE TABLES
class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    needs_password_change = db.Column(db.Boolean, nullable=False, default=True)
    registered_on = db.Column(db.DateTime, nullable=False)
    mfa_secret = db.Column(db.String(250))
    first_login = db.Column(db.Boolean, nullable=False)
    products = relationship('Product', back_populates='buyer')
    confirmed = db.Column(db.Boolean, nullable=False)
    confirmed_on = db.Column(db.DateTime, nullable=True)


class Product(db.Model):
    __tablename__ = 'products'
    id = db.Column(db.Integer, primary_key=True)
    buyer = relationship('User', back_populates='products')
    buyer_id = db.Column(db.Integer, ForeignKey('users.id'))
    stripe_product_id = db.Column(db.String(250), nullable=False)
    stripe_price_id = db.Column(db.String(250), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    added_on = db.Column(db.DateTime)


with application.app_context():
    db.create_all()


@application.route('/')
def home():
    return render_template('home.html', articles=get_active_products())


@application.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
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
                file_link_data={
                    'create': True
                }
            )
            url = file_obj.links.data[0].url
        stripe.Product.create(
            name=name,
            description=description,
            default_price_data={
                'currency': 'EUR',
                'unit_amount': int(float(price) * 100)
            },
            images=[url]
        )

        flash('Article was added successfully!', 'success')

        return redirect(url_for('home'))
    return render_template('admin/new_article.html')


@application.route('/articles')
@admin_required
def articles():
    return render_template('admin/articles.html', articles=get_active_products())  # Article.query.all()


@application.route('/article/<article_id>', methods=['GET', 'POST'])
@admin_required
def edit_article(article_id):
    article_to_edit = stripe.Product.retrieve(article_id)  # Article.query.get(int(article_id))
    current_price = stripe.Price.retrieve(article_to_edit.default_price)
    try:
        article_to_edit.price_amount = current_price.unit_amount / 100
    except:
        article_to_edit.price_amount = None
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
                unit_amount=int(float(price) * 100)
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
    product_to_delete = stripe.Product.retrieve(article_id)
    if product_to_delete.default_price:
        stripe.Product.modify(
            article_id,
            active=False
        )
    else:
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


@application.route('/add-to-chart/<article_id>')
@login_required
def add_to_chart(article_id):
    product_to_add = stripe.Product.retrieve(article_id)
    new_product = Product(
        buyer=current_user,
        buyer_id=current_user.id,
        stripe_product_id=article_id,
        stripe_price_id=product_to_add.default_price,
        quantity=1,
        added_on=datetime.now()
    )

    db.session.add(new_product)
    db.session.commit()

    flash('Successfully added product to chart.', 'success')
    return redirect(url_for('home'))


@application.route('/remove-from-chart/<article_id>')
@login_required
def remove_from_chart(article_id):
    delete_q = Product.__table__.delete()\
        .where(Product.stripe_product_id == article_id)\
        .where(Product.buyer_id == current_user.id)
    db.session.execute(delete_q)
    db.session.commit()
    flash('Successfully deleted product from chart.', 'success')
    return redirect(url_for('checkout'))


@application.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    checkout_products = Product.query.filter_by(buyer_id=current_user.id)
    articles = []
    for product in checkout_products:
        stripe_product = stripe.Product.retrieve(product.stripe_product_id)
        price = stripe.Price.retrieve(stripe_product.default_price).unit_amount
        try:
            stripe_product.price_amount = price / 100
            stripe_product.total_price = price / 100 * int(product.quantity)
        except:
            stripe_product.price_amount = None
            stripe_product.total_price = None
        stripe_product.quantity = product.quantity
        articles.append(stripe_product)
    if request.method == 'POST':
        buy_items = []
        for product in checkout_products:
            stripe_product = stripe.Product.retrieve(product.stripe_product_id)
            buy_items.append({
                'price': stripe_product.default_price,
                'quantity': product.quantity
            })
        try:
            checkout_session = stripe.checkout.Session.create(
                line_items=buy_items,
                mode='payment',
                success_url=YOUR_DOMAIN + url_for('checkout_success'),
                cancel_url=YOUR_DOMAIN + url_for('checkout_cancel'),
            )
        except Exception as e:
            return str(e)

        return redirect(checkout_session.url, code=303)
    return render_template('checkout.html', products=articles)


@application.route('/checkout/cancel')
def checkout_cancel():
    flash('Checkout was cancelled', 'warning')
    return redirect(url_for('checkout'))


@application.route('/checkout/success')
def checkout_success():
    flash('Checkout successful. Thank you for your purchase!', 'success')
    delete_q = Product.__table__.delete().where(Product.buyer_id == current_user.id)
    db.session.execute(delete_q)
    db.session.commit()
    return redirect(url_for('home'))


# HELPER
def get_active_products():
    all_products = stripe.Product.list(active=True)
    for product in all_products:
        if product.default_price:
            price = stripe.Price.retrieve(product.default_price)
            try:
                product.price_amount = price.unit_amount / 100
            except:
                product.price_amount = None
    return all_products


if __name__ == '__main__':
    application.run(debug=True)
