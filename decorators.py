from functools import wraps

from flask import flash, redirect, url_for, request
from flask_login import current_user, login_required


def admin_required(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated is False:
            flash('You are not signed in!', 'warning')
            return redirect(url_for('login'))
        if current_user.is_admin is False:
            flash('That is not an admin  account. Declined!', 'warning')
            return redirect(url_for('unauthorized'))
        return func(*args, **kwargs)

    return decorated_function


def check_confirmed(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if current_user.confirmed is False:
            flash(
                'This account is not activated yet! Look for the activation link in your mailbox!',
                'warning')
            return redirect(url_for('unconfirmed'))
        return func(*args, **kwargs)

    return decorated_function


def password_not_outdated(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated is False:
            flash('You are not signed in!', 'warning')
            return redirect(url_for('login'))
        if current_user.needs_password_change is True:
            flash('Your passwords needs to be updated!', 'warning')
            return redirect(url_for('reset_password'))
        return func(*args, **kwargs)

    return decorated_function
