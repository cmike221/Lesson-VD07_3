from flask import Blueprint, render_template, redirect, url_for, flash, request
from . import db
from .models import User
from flask_login import login_user, login_required, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError
from .forms import RegistrationForm  # Предполагается, что форма находится в файле forms.py

main = Blueprint('main', __name__)


@main.route('/')
def index():
    return render_template('login.html')


@main.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('main.profile'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html')


@main.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, email=email, password=hashed_password)

        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Your account has been created!', 'success')
            return redirect(url_for('main.login'))
        except IntegrityError:
            db.session.rollback()  # Откат изменений в случае ошибки
            flash('An account with this email already exists.', 'danger')

    return render_template('register.html', form=form)


@main.route('/profile')
@login_required
def profile():
    return render_template('profile.html')


@main.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.login'))
