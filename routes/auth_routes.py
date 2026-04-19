from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash

# Agar tum SQLAlchemy use kar rahe ho
from models import db, User   # ensure models.py me User model ho

auth = Blueprint('auth', __name__)

# -------------------------
# REGISTER / SIGNUP
# -------------------------
@auth.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # validation
        if not email or not password:
            flash('Please fill all fields', 'error')
            return redirect(url_for('auth.signup'))

        # check existing user
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists', 'error')
            return redirect(url_for('auth.signup'))

        # create new user
        hashed_password = generate_password_hash(password)

        new_user = User(email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Account created successfully!', 'success')
        return redirect(url_for('auth.login'))

    return render_template('signup.html')


# -------------------------
# LOGIN
# -------------------------
@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            flash('Login successful!', 'success')
            return redirect(url_for('main.dashboard'))  # change if needed
        else:
            flash('Invalid credentials', 'error')
            return redirect(url_for('auth.login'))

    return render_template('login.html')


# -------------------------
# LOGOUT
# -------------------------
@auth.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logged out successfully', 'success')
    return redirect(url_for('auth.login'))