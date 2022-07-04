from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)

app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# #CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))


# Line below only required once, when creating DB.
# db.create_all()

# Setup the user loader that sets up session cookie
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        user = request.form

        name_entered = user['name']
        email_entered = user['email']
        password_entered = user['password']

        pw_hash = generate_password_hash(password=password_entered,
                                         method='pbkdf2:sha256',
                                         salt_length=8)

        # Check whether a duplicate user exists and send message accordingly
        user_is_duplicate = User.query.filter_by(email=email_entered).first()

        if user_is_duplicate:
            flash('Email address already exists.')
            return redirect(url_for('register'))

        new_user = User(name=name_entered,
                        email=email_entered,
                        password=pw_hash)

        db.session.add(new_user)
        db.session.commit()

        # Create session cookie here?
        # login_user(new_user)
        return redirect(url_for('secrets', name=new_user.name))

    return render_template("register.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Authenticate user and redirect to secrets page
        user = request.form
        email_entered = user['email']
        password_entered = user['password']

        # Does the user exist?
        existing_user = User.query.filter_by(email=email_entered).first()

        if existing_user and check_password_hash(existing_user.password, password_entered):
            login_user(existing_user)
            return redirect(url_for('secrets', name=existing_user.name))

        # otherwise redirect to login and present message.
        flash('Please verify login credentials and try again.')
        return redirect(url_for('login'))

    return render_template("login.html")


@app.route('/secrets')
def secrets():
    name = request.args.get('name')
    return render_template("secrets.html", name=name)


@app.route('/logout')
def logout():
    pass


@app.route('/download')
def download():
    return send_from_directory(directory='', path='static/files/cheat_sheet.pdf')


if __name__ == "__main__":
    app.run(debug=True)
