from flask import Flask, render_template, url_for, redirect, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
import os
import json
from datetime import datetime
import geopy.distance

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = os.urandom(16).hex()
db = SQLAlchemy(app)
migrate = Migrate(app, db)

bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(80), nullable=False)
    phone = db.Column(db.Integer, nullable=False)
    level = db.Column(db.Integer, nullable=False)
    last_login = db.Column(db.DateTime, nullable=False)
    attendance = db.Column(db.Text)


class LoginForm(FlaskForm):
    username = StringField(validators=[
        InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
        InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')


# class RegisterForm(FlaskForm):
#     username = StringField(validators=[
#         InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
#
#     password = PasswordField(validators=[
#         InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
#
#     submit = SubmitField('Register')
#
#     def validate_username(self, username):
#         existing_user_username = User.query.filter_by(
#             username=username.data).first()
#         if existing_user_username:
#             raise ValidationError(
#                 'That username already exists. Please choose a different one.')


def log_write(log):
    fn = "logs.json"
    with open(fn, 'r') as f:
        fd = json.load(f)
    fd.append(log)
    with open(fn, 'w') as f:
        json.dump(fd, f)


@app.route('/')
def home():
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                user.last_login = datetime.now()
                db.session.commit()
                log_write({"user": f"{form.username.data}",
                           "tag": "login", "detail": "User Logged In", "time": f"{user.last_login}"})
                return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    log_write({
        "user": f"{current_user.username}", "tag": "logout", "detail": "User Logged Out", "time": f"{datetime.now()}"})
    logout_user()
    return redirect(url_for('login'))


@app.route('/attendance', methods=['GET', 'POST'])
@login_required
def attendance():
    if request.method == 'POST':
        t = 1
        attendance_data = json.loads(current_user.attendance) if current_user.attendance else []

        if current_user.attendance and attendance_data[-1] == datetime.now().strftime("%Y-%m-%d"):
            return "Attendance Marked"
        else:

            is_mobile = request.user_agent.platform in ('android', 'iphone')
            if is_mobile:
                lt = request.form['latitude']
                lg = request.form['longitude']
                if geopy.distance.distance((lt, lg), (20.240925, 85.825149)).m <= 100:
                    attendance_data.append(datetime.now().strftime("%Y-%m-%d"))
                    u = User.query.get(current_user.id)
                    u.attendance = json.dumps(attendance_data)
                    db.session.commit()
                    log_write({
                        "user": f"{current_user.username}", "tag": "Attendance Marked",
                        "detail": "User Attendance Successful",
                        "time": f"{datetime.now()}"})
                    return redirect(url_for('dashboard'))
    return render_template('attendance.html')

@app.route('/user_management', methods=['GET', 'POST'])
@login_required
def user_management():
    return render_template("user_management.html")


# @app.route('/register', methods=['GET', 'POST'])
# def register():
#     form = RegisterForm()
#
#     if form.validate_on_submit():
#         hashed_password = bcrypt.generate_password_hash(form.password.data)
#         new_user = User(username=form.username.data, password=hashed_password)
#         db.session.add(new_user)
#         db.session.commit()
#         return redirect(url_for('login'))
#
#     return render_template('register.html', form=form)
#

if __name__ == '__main__':
    app.run(debug=True)
