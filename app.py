from flask import Flask, render_template, url_for, redirect, request, send_from_directory
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
import random

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = "static"
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
    dob = db.Column(db.Date)
    level = db.Column(db.Integer, nullable=False)
    last_login = db.Column(db.DateTime)
    attendance = db.Column(db.Text)
    designation = db.Column(db.Text)
    address = db.Column(db.Text)
    address_proof = db.Column(db.Text)
    identity_proof = db.Column(db.Text)
    other_documents = db.Column(db.Text)
    basic_salary = db.Column(db.Integer)
    dearance_allowance = db.Column(db.Integer)
    house_rent_allowance = db.Column(db.Integer)
    conveyance_allowance = db.Column(db.Integer)
    manager = db.Column(db.Integer)



class Requests(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.Integer, nullable=False)
    receiver = db.Column(db.Integer, nullable=False)
    request_tag = db.Column(db.Text)
    info = db.Column(db.Text)
    approval = db.Column(db.Boolean)
    comments = db.Column(db.Text)

class msg(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.Integer, nullable=False)
    receiver = db.Column(db.Integer, nullable=False)
    msg_type = db.Column(db.Text)
    msg = db.Column(db.Text)
    read = db.Column(db.Boolean, default=False)

class LoginForm(FlaskForm):
    username = StringField(validators=[
        InputRequired(), Length(min=4, max=40)], render_kw={"placeholder": "Username"})

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

# @app.route('/clear_table', methods=['GET', 'POST'])
# def clear_table():
#     # Delete all rows from the table
#     db.session.query(Requests).delete()
#     db.session.commit()
#
#     return "Table cleared successfully"
def generate_username():
    while True:
        empid = random.randint(100000, 999999)
        if not User.query.filter_by(username=empid).first():
            return empid
def generate_reqid():
    while True:
        reqid = random.randint(100000, 999999)
        if not Requests.query.filter_by(id=reqid).first():
            return reqid


@app.route('/')
def home():
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        if user:
            if user.last_login == None:
                login_user(user)
                user.last_login = datetime.now()
                db.session.commit()
                return redirect(url_for("new_password"))

            elif bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                user.last_login = datetime.now()
                db.session.commit()
                log_write({"user": f"{form.username.data}",
                           "tag": "login", "detail": "User Logged In", "time": f"{user.last_login}"})
                return redirect(url_for('dashboard'))
        user = User.query.filter_by(email=form.username.data).first()

        if user:
            if user.last_login == None:
                login_user(user)
                user.last_login = datetime.now()
                db.session.commit()
                return redirect(url_for("new_password"))

            elif bcrypt.check_password_hash(user.password, form.password.data):
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
                if geopy.distance.distance((lt, lg), (20.27068051489967, 85.83349655952273)).m <= 100:
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


@app.route('/add_employee', methods=['GET', 'POST'])
@login_required
def add_employee():
    if request.method == 'POST':


        uname = generate_username()
        employee_info = {"username": uname,
                         "name": request.form['name'],
                         "email": request.form['email'],
                         "phone": request.form['phone'],
                         "dob": request.form['dob'],
                         "level": request.form['level'],
                         "designation": request.form['designation'],
                         "address": request.form['address'],
                         "basic_salary": request.form['basicSalary'],
                         "dearance_allowance": request.form['dearanceAllowance'],
                         "house_rent_allowance": request.form['houseRentAllowance'],
                         "conveyance_allowance": request.form['conveyanceAllowance'],
                         "manager": current_user.id,
                         "address_proof": str(uname) + "_Address_Proof.pdf",
                         "identity_proof": str(uname) + "_Identity_Proof.pdf",
                         "other_documents": str(uname) + "_Other_Documents.pdf"
                         }
        aproof = request.files.get("addressProof")
        aproof.save(os.path.join(app.config['UPLOAD_FOLDER'], str(uname) + "_Address_Proof.pdf"))
        idproof = request.files.get("identityProof")
        idproof.save(os.path.join(app.config['UPLOAD_FOLDER'], str(uname) + "_Identity_Proof.pdf"))
        odoc = request.files.get("otherDocuments")
        odoc.save(os.path.join(app.config['UPLOAD_FOLDER'], str(uname) + "_Other_Documents.pdf"))
        new_request = Requests(id=generate_reqid(),
                               request_tag="add_employee",
                               sender=current_user.id,
                               receiver=current_user.manager,
                               info=json.dumps(employee_info))
        db.session.add(new_request)
        db.session.commit()
        return redirect(url_for("user_management"))
    return render_template("add_employee.html")


@app.route('/download/<filename>')
@login_required
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/requests', methods=['GET', 'POST'])
@login_required
def requests():
    received_requests = Requests.query.filter_by(receiver=current_user.id).all()
    sent_request = Requests.query.filter_by(sender=current_user.id).all()
    req_data = {}
    for row in received_requests:
        req_data[row.id] = json.loads(row.info)
    for row in sent_request:
        req_data[row.id] = json.loads(row.info)
    return render_template("requests.html", sent_request=sent_request, received_requests=received_requests, User=User, datas=req_data)

@app.route('/sent_requests/<int:req>', methods=['GET', 'POST'])
@login_required
def sent_req_details(req):
    reqs = Requests.query.filter_by(id=req).first()
    req_data = {}
    req_data[req] = json.loads(reqs.info)
    return render_template("sent_req_details.html", request=reqs, datas=req_data, User=User)


@app.route('/received_requests/<int:req>', methods=['GET', 'POST'])
@login_required
def received_req_details(req):
    reqs = Requests.query.filter_by(id=req).first()
    req_data = {}
    req_data[req] = json.loads(reqs.info)
    return render_template("received_req_details.html", request=reqs, datas=req_data, User=User)

@app.route('/reject_request/<int:req>', methods=['GET', 'POST'])
@login_required
def reject_request(req):
    reqs = Requests.query.filter_by(id=req).first()
    reqs.comments = request.form["comment"]
    reqs.approval = False
    db.session.commit()
    return redirect(url_for("requests"))

@app.route('/approve_request/<int:req>', methods=['GET', 'POST'])
@login_required
def approve_request(req):
    reqs = Requests.query.filter_by(id=req).first()
    if reqs.request_tag == 'add_employee':
        datas = json.loads(reqs.info)
        new_user = User(username=datas['username'],
                         name=datas['name'],
                         email=datas['email'],
                         phone=datas['phone'],
                         dob=datetime.strptime(datas["dob"], '%Y-%m-%d').date(),
                         password=datas["dob"],
                         level=datas['level'],
                         designation=datas['designation'],
                         address=datas['address'],
                         basic_salary=datas['basic_salary'],
                         dearance_allowance=datas['dearance_allowance'],
                         house_rent_allowance=datas['house_rent_allowance'],
                         conveyance_allowance=datas['conveyance_allowance'],
                         manager=datas['manager'],
                         address_proof=datas['address_proof'],
                         identity_proof=datas['identity_proof'],
                         last_login=None,
                         other_documents=datas['other_documents'])
        db.session.add(new_user)
        db.session.commit()
        reqs.comments = "Done!"
        reqs.approval = True
        db.session.commit()
    return redirect(url_for("requests"))


@app.route('/new_password', methods=['GET', 'POST'])
@login_required
def new_password():
    if request.method == 'POST':
        new_pass = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_pass == confirm_password:
            hashed_password = bcrypt.generate_password_hash(new_pass)
            u = User.query.filter_by(id=current_user.id).first()
            u.password = hashed_password
            db.session.commit()
            return redirect(url_for('login'))  # Redirect to login page after setting password
        else:
            # Passwords don't match, handle accordingly (e.g., show an error message)
            pass

    return render_template('new_password.html')

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

@app.route('/messages', methods=['GET', 'POST'])
@login_required
def messages():



    return render_template('messages.html', user=User, msg=msg)
if __name__ == '__main__':
    app.run(debug=True)
