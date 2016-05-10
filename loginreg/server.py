from flask import Flask, request, redirect, render_template, session, flash
from mysqlconnection import MySQLConnector
import re

from flask.ext.bcrypt import Bcrypt

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9\.\+_-]+@[a-zA-Z0-9\._-]+\.[a-zA-Z]*$')
app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = "SHHHThisIsSecret!"
mysql = MySQLConnector(app, 'login')
@app.route('/')
def index():

    return render_template('index.html')

@app.route('/submit', methods = ['POST'])
def submit():

    if len(request.form['firstName']) < 2:
        flash("First name must have more than 2 letters")
    elif len(request.form['lastName']) < 2:
        flash("Last name must have more than 2 letters")
    elif len(request.form['email']) < 2:
        flash("Invalid Email Address!")
    elif not EMAIL_REGEX.match(request.form['email']):
        flash("Invalid Email Address!")
    elif len(request.form['password']) < 8:
        flash("Password must be more than 8 characters long")
    elif request.form['password'] != request.form['confirmPass']:
        flash("Passwords must match")
    # elif len(arr) > 0:
    #     flash("User Already Registered")
    else:
        # encrypts password
        pw_hash = bcrypt.generate_password_hash(request.form['password'])
        # store email address in the form
        query = "INSERT INTO users (first_name, last_name, email, password, date_created, date_updated) VALUES (:firstName, :lastName, :email, :password,  NOW(), NOW())"
        data = {
            'firstName': request.form['firstName'],
            'lastName': request.form['lastName'],
            'email': request.form['email'],
            'password': pw_hash,
        }

        mysql.query_db(query, data)

        session['newFirstName'] = request.form['firstName']
        session['newLastName'] = request.form['lastName']
        session['newEmail'] = request.form['email']
        return redirect ('/success')
    return redirect ('/register')

@app.route('/register')
def register():

    return render_template('registration.html')

@app.route('/login', methods = ['POST'])
def login():

    query = "SELECT * FROM users WHERE email = :email"
    data = {'email': request.form['email']}
    user =  mysql.query_db(query, data)
    password = request.form['password']

    if not user:
        flash( "Invalid Login")
        redirect ('/')
    elif (password == ""):
        flash("Please enter a password")
        return redirect ('/')
    elif (bcrypt.check_password_hash(user[0]['password'], password) == False):
        flash("Invalid Password")
        return redirect ('/')
    else:
        session['name'] =  user[0]['first_name']
        session['email'] = user[0]['email']

        return redirect ('/wall')

    return redirect ('/')


@app.route('/success')
def success():

    #shows registered information
    return render_template('success.html')

@app.route('/wall')
def wall():

    return render_template('wall.html')

@app.route ('/logout')
def logout():

    session.pop('name')
    session.pop('email')

    return redirect('/')

###Helper Functions

def minlength(dict, key, length):
    if len(dict[key] < length):
        flash("The {} has to have a minimum length of {}".format(key, length))


app.run(debug=True)
