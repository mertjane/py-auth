from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, UserMixin, login_required, current_user, logout_user
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
from email.message import EmailMessage
import ssl
import smtplib
import os
import random
import string


load_dotenv()  # Load environment variables

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DATABASE_URI']
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

verification_codes = {}

def generate_verification_code():
    return ''.join(random.choices(string.digits, k=6))

def send_verification_email(email, code):
    sender_email = os.environ['SENDER_MAIL']
    sender_pwd = os.environ['SENDER_KEY']

    message = f"Subject: Verification Code\n\nYour verification code is: {code}"

    context = ssl.create_default_context()
    
    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as server:
            server.login(sender_email, sender_pwd)
            server.sendmail(sender_email, email, message)
            print(f"Verification code sent to {email}")
    except Exception as e:
        print('Failed to send email:', e)



class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    activated = db.Column(db.Boolean, default=False)
    
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def send_activation_email(sender_email, sender_pwd, recipient_email, subject, template, activation_link):
    body = render_template(template, activation_link=activation_link)
    
    em = EmailMessage()
    em['From'] = sender_email
    em['To'] = recipient_email
    em['Subject'] = subject
    em.add_alternative(body, subtype='html')  # Set the content type to HTML

    context = ssl.create_default_context()

    with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
        try:
            smtp.login(sender_email, sender_pwd)
            smtp.sendmail(sender_email, recipient_email, em.as_string())
            print('Please check your mailbox to activate your account.')
        except Exception as e:
            print('Failed to send email:', e)


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_pwd():
    show_email_input = True
    show_verification_input = False
    show_new_pwd_input = False
    email = None
    user_id = None

    if request.method == 'POST':
        if 'email' in request.form:
            email = request.form['email']
            # Generate and store verification code
            verification_code = generate_verification_code()
            verification_codes[email] = verification_code

            # Send email with verification code (not implemented here)
            send_verification_email(email, verification_code)
            
            # Retrieve user from the database
            user = User.query.filter_by(email=email).first()
            print(user)
            
            if user:
                # Store user ID in session
                user_id = user.id
                session['email'] = email
                session['user_id'] = user_id
            
                # Render verification code input field
                show_email_input = False
                show_verification_input = True
            else:
                error = "User not found. Please try again."
                print("User not found for email:", email)
                return render_template('forgot_pwd.html', show_email_input=True, error=error)

        elif 'verification_code' in request.form:
            verification_code = request.form.get('verification_code')

            if verification_code in verification_codes.values():

                # Correct verification code, render new password input fields
                show_email_input = False
                show_verification_input = False
                show_new_pwd_input = True
            else:
                # Incorrect verification code, show error message
                error = "Incorrect verification code. Please try again."
                return render_template('forgot_pwd.html', show_email_input=False, show_verification_input=True, email=email, error=error)

        elif 'new_pwd' in request.form and 'confirm_new_pwd' in request.form:
            new_password = request.form['new_pwd']
            confirm_new_password = request.form['confirm_new_pwd']

            # Validate new password and confirm password
            if new_password == confirm_new_password:
                user_id = session.get('user_id')
                if user_id:
                    # Retrieve user from the database using ID
                    user = User.query.get(user_id)
                    if user:
                        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
                        # Update user's password in the database
                        user.password = hashed_password
                        db.session.commit()
                        # Redirect to login page
                        return redirect(url_for('login'))
                    else:
                        error = "User not found. Please try again."
                        print("User not found for ID:", user_id)
                        return render_template('forgot_pwd.html', show_email_input=False, show_verification_input=False, show_new_pwd_input=True, email=email, error=error)
                else:
                    error = "User ID not found in session. Please try again."
                    return render_template('forgot_pwd.html', show_email_input=False, show_verification_input=False, show_new_pwd_input=True, email=email, error=error)
            else:
                error = "Passwords do not match. Please try again."
                return render_template('forgot_pwd.html', show_email_input=False, show_verification_input=False, show_new_pwd_input=True, email=email, error=error)

    # Pass the current user's email to the template
    email = session.get('email')
    return render_template('forgot_pwd.html', show_email_input=show_email_input, show_verification_input=show_verification_input, show_new_pwd_input=show_new_pwd_input, email=email)





@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            # Redirect to dashboard or any other page after successful login
            return redirect(url_for('dashboard'))
        else:
            # Display error message for incorrect username or password
            error = "Invalid username or password. Please try again."
            return render_template('login.html', error=error)
        
    return render_template('login.html')

@app.route('/activate')
def activate():
    return render_template('activate.html')

@app.route('/activated/<username>')
def activated_account(username):
    # Find the user by username
    user = User.query.filter_by(username=username).first()
    if user:
        # Activate the user's account
        user.activated = True
        db.session.commit()
        return render_template('activated.html')
    else:
        return "Invalid activation link."

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    username = current_user.username
    return render_template('dashboard.html', username=username)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        password_confirm = request.form['password_confirm']
        
        # Check if any field is empty
        if not username or not email or not password or not password_confirm:
            return render_template('register.html', error="All fields are required.")
        
        # Check if username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return render_template('register.html', error="Username already exists.")
        
        # Check if passwords match
        if password != password_confirm:
            return render_template('register.html', error="Passwords do not match.")
        
        hashed_password = bcrypt.generate_password_hash(password)
        
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        
        # Send activation email
        activation_link = f"{os.environ['URL']}/activated/{username}"
        send_activation_email(os.environ['SENDER_MAIL'], os.environ['SENDER_KEY'], email, "Account Activation", "email_template.html", activation_link)
        
        return redirect(url_for('activate'))
    return render_template('register.html')


if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    app.run(debug=True)