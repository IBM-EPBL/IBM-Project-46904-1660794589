from flask import Flask ,render_template, request, redirect, url_for, session, g, flash
from passlib.hash import sha256_crypt
from dotenv import load_dotenv
from datetime import timedelta
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from datetime import datetime
import ibm_db
import os
import requests
import json


load_dotenv()

app = Flask(__name__)

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

app.permanent_session_lifetime = timedelta(days=30)

@app.route("/")
def home():
    if g.email:
        return render_template('index.html')
    else:
        return redirect(url_for('login'))

@app.before_request
def before_request():
    g.email = None
    
    if 'email' in session:
        g.email = session['email']


# auth routes

@app.route('/login', methods=['POST', "GET"])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        sql = "select * from FVS49663.USER where username = ?"
        stmt = ibm_db.prepare(conn,sql)
        ibm_db.bind_param(stmt, 1, username)
        ibm_db.execute(stmt)
        user = ibm_db.fetch_assoc(stmt)
        if user['IS_VERIFIED']:
            if user:
                print(user)
                print(user['ID'])
                user_password = user['PASSWORD']
                if(sha256_crypt.verify(password, user_password)):
                    session.permanent = True
                    session['id'] = user['ID']
                    session['email'] = user['EMAIL']
                    session['interest'] = user['INTEREST']
                    session['is_loggedin'] = True
                    return redirect(url_for('home'))
                else:
                    flash('Password is incorrect')
                    return render_template('auth/login.html')
            else:
                flash('Username is incorrect')
                return render_template('auth/login.html')
        else:
            return 'Please verify your account'
    else:
        return render_template('auth/login.html')

@app.route('/logout')
def logout():
    if 'email' in session:
        session.pop('id',None)
        session.pop('email',None)
        session.pop('is_loggedin',None) 
        return redirect(url_for('login'))

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
        interest = request.form.get('interest')
        is_verified = False

        sql = "INSERT INTO FVS49663.USER(username,name,email,phno,state,city,password,interest,is_verified) VALUES('{}','{}','{}','{}','{}','{}','{}','{}','{}')".format(username,name,email,phno,state,city,encrypt_password,interest,is_verified)
        ibm_db.exec_immediate(conn,sql)


        token = s.dumps(email, salt='email-confirm')
        msg = Message('Confirm Email', sender= os.getenv('FROM_EMAIL'), recipients=[email])
        link = url_for('confirm_email', token=token + ',' +username, _external=True)
        msg.body = 'Your link is {}'.format(link)
        mail.send(msg)
        return render_template('auth/verification_email_send.html')
    else:
        return render_template('auth/register.html')


@app.route('/confirm_email/<token>/')
def confirm_email(token):
    data = token.split(',')
    print(data)
    try:
        email = s.loads(data[0], salt='email-confirm', max_age=3600)

    except SignatureExpired:
        return '<h1>The token is expired!</h1>'
        
    sql = "UPDATE FVS49663.USER set is_verified = True where username = '{}'".format(data[1])
    ibm_db.exec_immediate(conn,sql)
    return render_template('auth/account_activation_success.html',is_success =  True)




# Job routes
@app.route('/jobs',methods=['POST','GET'])
def jobs():
    if g.email:
        if request.method == 'POST': 
            search_query = request.form.get('search_query')
            req = requests.get("http://api.adzuna.com/v1/api/jobs/gb/search/1?app_id=b8adcac4&app_key=68108197016f443e2c24af0587b39471&results_per_page=50&what='{}'&content-type=application/json".format(search_query))
            jobs = json.loads(req.content)
            return render_template('jobs.html', jobs = jobs['results'])
        else:
            sql = "select * from FVS49663.USER where id = ?"
            stmt = ibm_db.prepare(conn,sql)
            ibm_db.bind_param(stmt, 1, session['id'])
            ibm_db.execute(stmt)

            user = ibm_db.fetch_assoc(stmt)

            req = requests.get("http://api.adzuna.com/v1/api/jobs/gb/search/1?app_id=b8adcac4&app_key=68108197016f443e2c24af0587b39471&results_per_page=50&what='{}'&content-type=application/json".format(user['INTEREST']))
            jobs = json.loads(req.content)
            return render_template('jobs.html', jobs = jobs['results'])
    else:
        return redirect(url_for('login'))


@app.route('/profile',methods=['POST','GET'])
def profile():
    if g.email:
        if request.method == 'POST':
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')
            if password == confirm_password:
                print("Ok")
                user = session['id']
                encrypt_password = sha256_crypt.encrypt(password)
                sql = "UPDATE FVS49663.USER set password = '{}' where id = '{}'".format(encrypt_password,user)
                ibm_db.exec_immediate(conn,sql)
                return redirect(url_for('profile'))
        else:
            sql = "select * from FVS49663.USER where id = ?"
            stmt = ibm_db.prepare(conn,sql)
            ibm_db.bind_param(stmt, 1, session['id'])
            ibm_db.execute(stmt)

            user = ibm_db.fetch_assoc(stmt)

            sql1 = "select * from FVS49663.EDUCATION where id = ?"
            stmt1 = ibm_db.prepare(conn,sql1)
            ibm_db.bind_param(stmt1, 1, session['id'])
            ibm_db.execute(stmt1)

            educations = []
            dictionary = ibm_db.fetch_both(stmt1)
            while dictionary != False:
                educations.append(dictionary)
                dictionary = ibm_db.fetch_both(stmt1)

            print(educations)
            return render_template('profile.html',user={"user":user,"educations":educations})

    else:
        return redirect(url_for('login'))

@app.route("/add_education",methods=['POST','GET'])
def add_education():
    if g.email:
        if request.method == 'POST':
            college_name = request.form.get('college_name')
            degree = request.form.get('degree')
            grade = request.form.get('grade')
            userid = session['id']
            sql = "insert into FVS49663.EDUCATION(college_name,degree,grade,userid) values ('{}','{}','{}','{}')".format(college_name,degree,grade,userid)
            ibm_db.exec_immediate(conn,sql)
            return redirect(url_for('profile'))
        else:
            return render_template('add_education.html')
    else:
        return redirect(url_for('login'))


@app.route("/update_profile",methods=['POST','GET'])
def update_profile():
    if g.email:
        if request.method == 'POST':
            phno = str(request.form.get('phone_number'))
            state = request.form.get('state')
            city = request.form.get('city')
            interest = request.form.get('interest')
            userid = session['id']

            sql = "UPDATE FVS49663.USER set phno = '{}',state = '{}',city = '{}',interest = '{}' where id = '{}'".format(phno,state,city,interest,userid)
            ibm_db.exec_immediate(conn,sql)
            return redirect(url_for('profile'))
        else:
            sql = "select * from FVS49663.USER where id = ?"
            stmt = ibm_db.prepare(conn,sql)
            ibm_db.bind_param(stmt, 1, session['id'])
            ibm_db.execute(stmt)

            user = ibm_db.fetch_assoc(stmt)
            return render_template('update_profile.html',user = user)
    else:
        return redirect(url_for('login')) 