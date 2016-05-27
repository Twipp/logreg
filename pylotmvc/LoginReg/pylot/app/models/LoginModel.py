"""
    Sample Model File

    A Model should be in charge of communicating with the Database.
    Define specific model method that query the database for information.
    Then call upon these model method in your controller.

    Create a model using this template.
"""
from system.core.model import Model
import re


class LoginModel(Model):
    def __init__(self):
        super(LoginModel, self).__init__()

    def create_user(self, info):


        EMAIL_REGEX = re.compile(r'^[a-za-z0-9\.\+_-]+@[a-za-z0-9\._-]+\.[a-za-z]*$')
        validations = []

        print info['first_name']
        print info['last_name']
        print info['email']
        print info['password']

        if(len(info['first_name']) < 2):
            validations.append("Name must be more than two characters long")
        elif(len(info['last_name']) < 2):
            validations.append("Last name must be more than two characters long")

        if not info['email']:
            validations.append("Email cannot be blank")
        elif not EMAIL_REGEX.match(info['email']):
            validations.append('Email format must be valid!')
        elif (self.emailCheck(info)):
            validations.append('User Already Registered')

        if not info['password']:
            validations.append("Password cannot be blank")
        elif (info['password'] != info['confirm_pass']):
            validations.append('Password must match')

        if validations:
            return {"status": False, "errors": validations}

        else:

            password = info['password']

            hashed_pw = self.bcrypt.generate_password_hash(password)

            register_query = "INSERT INTO users (first_name, last_name, email, password, created_at, updated_at) VALUES(:first_name,:last_name, :email, :pw_hash, NOW(), NOW())"

            data = {
                'first_name' : info['first_name'],
                'last_name' : info['last_name'],
                'email' : info['email'],
                'pw_hash' : hashed_pw
            }

            self.db.query_db(register_query, data)
            return {"status": True, "errors": validations}


    def login_user(self, info):

        emailCheck = self.emailCheck(info)
        passCheck = self.passCheck(info)
        errors = []

        if (emailCheck == False):
            errors.append('User is not registered')
        elif (passCheck == False):
            errors.append('Password is invalid')

        if (errors):
            return{"status": True, 'errors': errors}

        else:
            return{'status': False, 'errors':errors}






    ##Helper Functions

    def emailCheck(self, info):

        emailCheck = "SELECT email FROM users WHERE (email = :userEmail)"
        emailData = {
            'userEmail': info['email']
        }
        check =  self.db.query_db(emailCheck, emailData)

        if (check):
            return True
        else:
            return False

    def passCheck(self, info):

        passCheck = "SELECT email FROM users WHERE (password = :userPass)"
        passData = {
            'userPass': info['password']
        }
        check =  self.db.query_db(passCheck, passData)

        if (check):
            return True
        else:
            return False
