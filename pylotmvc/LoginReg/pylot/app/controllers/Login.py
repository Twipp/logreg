"""
    Sample Controller File

    A Controller should be in charge of responding to a request.
    Load models to interact with the database and load views to render them to the client.

    Create a controller using this template
"""
from system.core.controller import *

class Login(Controller):
    def __init__(self, action):
        super(Login, self).__init__(action)
        """
            This is an example of loading a model.
            Every controller has access to the load_model method.
        """
        self.load_model('LoginModel')
        self.db = self._app.db

        """

        This is an example of a controller method that will load a view for the client

        """

    def index(self):
        """
        A loaded model is accessible through the models attribute
        self.models['WelcomeModel'].get_users()

        self.models['WelcomeModel'].add_message()
        # messages = self.models['WelcomeModel'].grab_messages()
        # user = self.models['WelcomeModel'].get_user()
        # to pass information on to a view it's the same as it was with Flask

        # return self.load_view('index.html', messages=messages, user=user)
        """
        return self.load_view('index.html')

    def register(self):

        user_data = {
            "first_name": request.form['First Name'],
            "last_name": request.form['Last Name'],
            "email": request.form['Email'],
            "password": request.form['Password'],
            "confirm_pass": request.form['ConfirmPass']
        }

        reg_status = self.models["LoginModel"].create_user(user_data)

        if reg_status['status'] == False:

            print "FALSE"

            #Will switch to flash messaging!!!!!!!!
            for message in reg_status['errors']:
                print message

            return self.load_view('index.html', reg_status = reg_status)

        else:

            print "REGISTERED!"

            return redirect('/registered')

    def login(self):

        email_check = request.form['Email']

        user_data = {
            "email": request.form['Email'],
            "password": request.form['Password']
        }

        login_status = self.models['LoginModel'].login_user(user_data)


        if not(email_check):

            error = ["Must Enter Email"]
            email_status = {"status": True, "errors": error}
            return self.load_view('index.html', login_status = email_status)

        elif (login_status['status'] == True):
            #figure out how to send check messgaes without rendering
            return self.load_view('index.html', login_status = login_status)
        else:
            return redirect('/loggedin')

    def registered(self):

        return self.load_view('registered.html')

    def loggedin(self):

        return self.load_view('loggedin.html')
