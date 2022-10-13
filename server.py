from flask import Flask, request, render_template
from flask_cors import CORS, cross_origin
from pymongo import MongoClient
from bson import json_util
from datetime import datetime
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from email.message import EmailMessage
from dotenv import load_dotenv
from os.path import join, dirname
from dotenv import load_dotenv
import requests
import json
import uuid
import hashlib
import os
import smtplib, ssl
import base64
import flask
import google.auth
import google_auth_oauthlib.flow

CLIENT_SECRETS_FILE = 'credentials.json'
#os.environ.get('CLIENT_SECRETS_FILE')
API_SERVICE="gmail"
API_VERSION="v1"
SCOPES = [
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/gmail.send',
    'https://www.googleapis.com/auth/gmail.compose'
]

admin_name = os.environ.get('ADMIN_NAME')

dotenv_path = join(dirname(__file__), '.env')
load_dotenv(dotenv_path)

server_port = os.environ.get("PORT")

app = Flask(__name__)
app.secret_key = os.environ.get('CLIENT_SECRET')
CORS(app)

#client = MongoClient(host=os.environ.get("DBHOST"), port=int(os.environ.get('DBPORT')))
client = MongoClient(os.environ.get("DBHOST"))
db = client[os.environ.get('DB')] # Uses dictionary-style access to protect MongoDB database name
users = db.users
blogs = db.blogs
categories = db.categories
comments = db.comments

# Authorizes Gmail API via OAuth2
# The file token.json stores the user's access and refresh tokens, and is
# created automatically when the authorization flow completes for the first
# time.
@app.route('/authorize')
def authorize():
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, scopes=SCOPES)
    flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

    authorization_url, state = flow.authorization_url(access_type='offline',include_granted_scopes='true')
    print(authorization_url)

    # Store the state so the callback can verify the auth server response.
    flask.session['state'] = state

    return flask.redirect(authorization_url)

@app.route('/oauth2callback')
def oauth2callback():
    # Specify the state when creating the flow in the callback so that it can
    # verified in the authorization server response.
    state = flask.session['state']

    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
    flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

    # Use the authorization server's response to fetch the OAuth 2.0 tokens.
    auth_response = flask.request.url
    flow.fetch_token(authorization_response=auth_response)

    # Store credentials in the database
    credentials = flow.credentials
    users.update_one({"username":admin_name},{"$set": {"creds": credentials_to_dict(credentials)}})

    return flask.redirect(flask.url_for('handle_users'))

def credentials_to_dict(credentials):
  return {'token': credentials.token,
          'refresh_token': credentials.refresh_token,
          'token_uri': credentials.token_uri,
          'client_id': credentials.client_id,
          'client_secret': credentials.client_secret,
          'scopes': credentials.scopes}

# If user is already logged in then return user info
@app.route('/', methods=['GET'])
def handle_users():
    user = users.find_one({'username':admin_name})

    #if user['creds'] is None:
    authorize()

    user_uuid = request.args.get('uuid')

    return json_util.dumps(users.find_one({'uuid':user_uuid})) if user_uuid is not None else ''

# Handles all blog inquiries
@app.route("/blog", methods=['GET','POST'])
def handle_blog():

    if request.method == 'GET':
        blog_uuid = request.args.get('uuid');

        # if a specified blog is selected then it returns a blog with the specified UUID otherwise it returns all blogs
        if blog_uuid != '':
            return json_util.dumps(blogs.find_one({"uuid": blog_uuid}))
        else:
            return json_util.dumps(blogs.find())

    else:
        formdata = request.get_json()['data']
        title = formdata['title']
        summary = formdata['summary']
        content = formdata['content']
        categories = formdata['categories']

        # If a specified blog is selected then it updates the blog with new info, otherwise it inserts a new blog entry
        if formdata['blog_uuid'] != "":
            blog_uuid = formdata['blog_uuid'];

            updated_blog = {
                "title" : title,
                "summary": summary,
                "content" : content,
                "categories" : categories,
                "modified_date" : datetime.now()
            }
            blogs.update_one({'uuid':blog_uuid}, {"$set": updated_blog})

            return ''

        else:
            new_blog = {
                "uuid" : str(uuid.uuid4()),
                "title" : title,
                "summary": summary,
                "content" : content,
                "categories" : categories,
                "comments": [],
                "creation_date" : datetime.now(),
                "modified_date" : datetime.now()
            }
            blogs.insert_one(new_blog)

            return ''

# Handles user account inquirues
@app.route("/login", methods=['POST'])
def handle_users_login():
    username = request.get_json()['data']['username']
    password = request.get_json()['data']['password']

    user = users.find_one({"username":username})

    # If user exists in database then return user info otherwise return None
    if user is not None:

        # Hashes password using SHA256 algorithm with salt value provided by an existing user
        key = hashlib.pbkdf2_hmac('sha256',password.encode('utf-8'),user['salt'],100000)
        hash = key + user['salt']
    else:
        return ''

    # If both hash values are equal then return user object otherwise return None
    return json_util.dumps(user) if user['password']==hash else ''

# Handles inquiries to register new users
@app.route("/register", methods=['POST'])
def handle_users_register():
    formdata = request.get_json()['data'];
    username = formdata['username']

    user = users.find_one({"username":username})

    # If user doesn't exist then create one otherwise return None
    if user is None:

        # Generates a new salt value for the user to be registered, and uses it to hash user password using SHA256 algorithm
        salt = os.urandom(23)
        key = hashlib.pbkdf2_hmac('sha256',formdata['password'].encode('utf-8'),salt,100000)
        storage = key + salt

        # Generates a new UUID for the new user
        new_user = {
            "uuid": str(uuid.uuid4()),
            "username": username,
            "password": storage,
            "salt": salt,
            "email": formdata['email'],
            "firstname": formdata['fname'],
            "lastname": formdata['lname'],
            "birthday": datetime.strptime(formdata['bdate'], '%Y-%m-%dT%H:%M:%S.%fZ'),
            "phone": formdata['phone'],
            "role": "user",
            "creation_date": datetime.now()
        }

        # Generates an email template to send to new users upon successful registration
        try:
            user = users.find_one({'username':admin_name})
            creds = user['creds']

            # Load credentials from the session.
            credentials = google.oauth2.credentials.Credentials(
                creds["token"],
                refresh_token = creds["refresh_token"],
                token_uri = creds["token_uri"],
                client_id = creds["client_id"],
                client_secret = creds["client_secret"],
                scopes = creds["scopes"]
            )

            gmail = build(API_SERVICE, API_VERSION, credentials=credentials)

            message = EmailMessage()

            message.set_content('Hi '+formdata['fname']+',\n\nThank you for registering with us!')

            message['To'] = formdata['email']
            message['Subject'] = "Welcome to Mugiesshan's Blog"

            # encoded message
            encoded_message = base64.urlsafe_b64encode(message.as_bytes()) \
                .decode()

            create_message = {
                'raw': encoded_message
            }
            # pylint: disable=E1101
            send_message = (gmail.users().messages().send
                            (userId="me", body=create_message).execute())
            print(F'Message Id: {send_message["id"]}')
        except HttpError as error:
            print(F'An error occurred: {error}')
            send_message = None

        users.insert_one(new_user)

    return ''

# Returns all blogs that contain a specified category value
@app.route("/category/", methods=['GET'])
def handle_categories():
    category = request.args.get('category')

    return json_util.dumps(blogs.find({"categories": {"$regex": category}}))

if __name__ == '__main__':
    app.run(port=server_port)
