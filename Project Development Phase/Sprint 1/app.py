from flask import Flask ,render_template, request, redirect, url_for, session, g, flash
from passlib.hash import sha256_crypt
from dotenv import load_dotenv
from datetime import timedelta
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from flask_ckeditor import CKEditor
import ibm_db
import os

load_dotenv()

app = Flask(__name__)
ckeditor = CKEditor(app)

DATABASE_NAME = os.getenv("DATABASE_NAME")
HOST_NAME = os.getenv("HOST_NAME")
PORT_NUMBER = os.getenv("PORT_NUMBER")
USER_ID = os.getenv("USER_ID")
PASSWORD = os.getenv("PASSWORD")

# IBM cloud connection string
conn = ibm_db.connect(f"DATABASE={DATABASE_NAME};HOSTNAME={HOST_NAME};PORT={PORT_NUMBER};SECURITY=SSL;SSLServerCertificate=DigiCertGlobalRootCA.crt;UID={USER_ID};PWD={PASSWORD}",'','')

# secret key
app.secret_key = os.getenv('SECRET_KEY')

# configuration of mail
app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

mail = Mail(app)
s = URLSafeTimedSerializer('Thisisasecret!')

app.permanent_session_lifetime = timedelta(seconds=20)

@app.route("/")
def home():
    if g.email:
        return session['email']
    else:
        return redirect(url_for('login'))

@app.before_request
def before_request():
    g.email = None
    
    if 'email' in session:
        g.email = session['email']

@app.route('/login', methods=['POST', "GET"])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        sql = "select * from FVS49663.TTUSER where username = ?"
        stmt = ibm_db.prepare(conn,sql)
        ibm_db.bind_param(stmt, 1, username)
        ibm_db.execute(stmt)
        user = ibm_db.fetch_assoc(stmt)
        if user:
            print(user)
            print(user['ID'])
            user_password = user['PASSWORD']
            
            if(sha256_crypt.verify(password, user_password)):
                session.permanent = True
                session['id'] = user['ID']
                session['email'] = user['EMAIL']
                session['is_loggedin'] = True
                if user['ROLE'] == 'hr':
                    return redirect(url_for('hr_dashboard'))
                else:
                    return redirect(url_for('home'))
            else:
                flash('Password is incorrect')
                return render_template('auth/login.html')
        else:
            flash('Username is incorrect')
            return render_template('auth/login.html')
    else:
        return render_template('auth/login.html')

@app.route('/logout')
def logout():
    if 'email' in session:
        session.pop('id',None)
        session.pop('email',None)
        session.pop('is_loggedin',None) 
        return redirect(url_for('login_page'))

@app.route('/register', methods=['POST', "GET"])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        phno = str(request.form.get('phone_number'))
        state = request.form.get('state')
        city = request.form.get('city')
        password = request.form.get('password')
        encrypt_password = sha256_crypt.encrypt(password)

        name = first_name + ' ' + last_name
        role = 'user'
        is_verified = False

        sql = "INSERT INTO FVS49663.TTUSER(username,name,email,phno,state,city,password,role,is_verified) VALUES('{}','{}','{}','{}','{}','{}','{}','{}','{}')".format(username,name,email,phno,state,city,encrypt_password,role,is_verified)
        ibm_db.exec_immediate(conn,sql)


        token = s.dumps(email, salt='email-confirm')
        msg = Message('Confirm Email', sender= os.getenv('FROM_EMAIL'), recipients=[email])
        link = url_for('confirm_email', token=token + ',' +username, _external=True)
        msg.body = 'Your link is {}'.format(link)
        mail.send(msg)
        return render_template('auth/verification_email_send.html')
    else:
        return render_template('auth/register.html')

@app.route('/hr_register', methods=['POST', "GET"])
def hr_register():
    if request.method == 'POST':
        username = request.form.get('username')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        phno = str(request.form.get('phone_number'))
        state = request.form.get('state')
        city = request.form.get('city')
        password = request.form.get('password')
        encrypt_password = sha256_crypt.encrypt(password)

        name = first_name + ' ' + last_name
        role = 'hr'
        is_verified = False

        sql = "INSERT INTO FVS49663.TTUSER(username,name,email,phno,state,city,password,role,is_verified) VALUES('{}','{}','{}','{}','{}','{}','{}','{}','{}')".format(username,name,email,phno,state,city,encrypt_password,role,is_verified)
        ibm_db.exec_immediate(conn,sql)


        token = s.dumps(email, salt='email-confirm')
        msg = Message('Confirm Email', sender= os.getenv('FROM_EMAIL'), recipients=[email])
        link = url_for('confirm_email', token=token + ',' +username, _external=True)
        msg.body = 'Your link is {}'.format(link)
        mail.send(msg)
        return render_template('auth/verification_email_send.html')
    else:
        return render_template('auth/register.html',type = "hr")

@app.route('/confirm_email/<token>/')
def confirm_email(token):
    data = token.split(',')
    print(data)
    try:
        email = s.loads(data[0], salt='email-confirm', max_age=3600)

    except SignatureExpired:
        return '<h1>The token is expired!</h1>'
        
    sql = "UPDATE FVS49663.TTUSER set is_verified = True where username = '{}'".format(data[1])
    ibm_db.exec_immediate(conn,sql)
    return render_template('auth/account_activation_success.html',is_success =  True)


@app.route('/forgot_password')
def forgot_password():
    return render_template('auth/reset_password.html')

@app.route('/hr_dashboard')
def hr_dashboard():
    return render_template('hr/home.html') 

@app.route('/add_company')
def add_company():
    return render_template('hr/add_company.html') 

@app.route('/hr_jobs_added')
def hr_jobs_added():
    return render_template('hr/jobs_list.html')   