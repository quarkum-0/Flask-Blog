It is a blogging app made from flask.
You can view someones' post without logging in.
But you have to be logged in to create a post.
If you are the poster you can delete or edit your post.
You can also delete your account whenever you want.
Admin access is given by users' unique id generated the the code.
Admin has access to delete or edit any post.
You can add cool profile pics from your PC and write about you on dashboard(profile page).
You can see who has posted and at what time(in UTC) and day.
Your data and profile is saved for future log-ins.
You can make only one profile per email but you can update your profile as many times as you want.
You cannot change your password once it is set.
Even without logging in you can see who else is using the app by both their name and email address.



****Admin access is given to only to the first user(You can change that)****
****Google login is work in progress(Nearly completed)****





For the app to work you have to follow these steps.

Use git bash

pip install flask
export FLASK_ENV=development
export FLASK_APP=app.py
pip install flask-wtf
pip install flask-sqlalchemy
pip install mysql-connector
pip install mysql-connector-python
pip install mysql-connector-python-rf
pip install flask-migrate
pip install flask-ckeditor
pip install flask-login
pip install flask-authlib
pip install google-api-python-client
pip install google-auth
pip install jso
pip install uuid
pip install google-auth



flask shell
db.create_all()
exit()


Create Google API
Add People API too(birthday and gender)(If you don't want to do that just change the scope in client_kwargs)
(I have provided the link in comment where you can find different scopes)
Use client-id and client-secret


Put these links in Authorized redirect URIs
http://localhost:5000/login
http://localhost:5000/authorize
http://127.0.0.1:5000/sign-in/google
http://localhost:5000/login/google
http://127.0.0.1:5000/callback


go on http://localhost:5000 to access the web page.


Note: I am using SQLite but have given the codes in comments
      if you want to use MySql.

      If you want to add other users to be admin you just
      have to add it in the code(not more than 2 lines are required)