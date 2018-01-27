import os
from db_setup import Base, User, Character, BlogEntry, secret_key, _get_date
from flask import Flask, jsonify, request, url_for, abort
from flask import g, render_template, flash, redirect
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine
from flask_httpauth import HTTPBasicAuth
import random
import string
import json
import httplib2
import requests
from flask import make_response
from flask import session as login_session
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
from werkzeug.utils import secure_filename
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger

UPLOAD_FOLDER = 'static/user-imgs'
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])

# METADATA: All of this creates and runs the database.

auth = HTTPBasicAuth()

engine = create_engine('sqlite:///database.db')

Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# This is where the JSON file is referenced for later use.


CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Restaurant Menu Application"

# Google Sign-In


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate State Token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.', 401))
        response.headers['Content-type'] = 'application/json'
        return response
    # Auth Code
    code = request.data

    try:
        # Auth Code into Credentials
        oauth_flow = flow_from_clientsecrets(
            'client_secrets.json', scope='openid email')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(json.dumps(
            'Failed to upgrade the authorization code.'), 401)
        response.headers['Content-type'] = 'application/json'
        return response

    # Check if access token is valid
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' %
           access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If token error, abort
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-type'] = 'application/json'
        return response

    # Verify Access token is for Intended User.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(json.dumps(
            "Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-type'] = 'application/json'
        return response

    # Verify Token is for this App
    if result['issued_to'] != CLIENT_ID:
        response = make_response(json.dumps(
            "Token's client ID does not match app's"), 401)
        print("Token's client ID does not match app's.")
        response.headers['Content-type'] = "application/json"
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps(
            'Current user is already connected'), 200)
        response.headers['Content-type'] = 'application/json'
        return response

    # Store access token in session for later use
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get User Info
    userinfo_url = 'https://www.googleapis.com/oauth2/v1/userinfo'
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['email'] = data['email']
    login_session['provider'] = 'google'

    # See if user exists if it doesn't, make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += 'Logged in as %s' % login_session['username']
    return output

# Creating Users and retrieving user data via id/email through the database


def createUser(login_session):
    newUser = User(username=login_session[
                   'username'], email=login_session['email'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

# GOOGLE DISCONNECT


@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(json.dumps(
            'Current user not connected.'), 401)
        response.headers['Content-type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps(
            'Failed to revoke token for given user.'), 400)
        response.headers['Content-type'] = 'application/json'
        return response

# This Here Verifies Passwords for API Usage


@auth.verify_password
def verify_password(username_or_token, password):
    user_id = User.verify_auth_token(username_or_token)
    if user_id:
        user = session.query(User).filter_by(id=user_id).one()
    else:
        user = session.query(User).filter_by(
            username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True

# JSON APIs to get Information

#######################
# Websites Start Here #
#######################


@app.route('/', methods=["GET", "POST"])
@app.route('/home', methods=["GET", "POST"])
def home():
    if 'username' in login_session:
        currentuser = session.query(User).filter_by(
            username=login_session['username']).one()
        allUserChars = session.query(Character).filter_by(
            user_id=currentuser.id).all()
        allUserPosts = session.query(BlogEntry).filter_by(
            user_id=currentuser.id).all()
        if request.method == "POST":
            entry = session.query(BlogEntry).filter_by(
            id=request.form['value']
            ).one()
            session.delete(entry)
            session.commit()
            return redirect(url_for('home', login_session=login_session))
        return render_template('home.html', allUserPosts=allUserPosts,
                               login_session=login_session,
                               currentuser=currentuser,
                               allUserChars=allUserChars)
    else:
        return render_template('index.html', login_session=login_session)


@app.route('/correspondents')
def correspondents():
    return redirect(url_for('viewCor', page=1))


@app.route('/correspondents/<int:page>', methods=['GET'])
def viewCor(page):
    post_list = session.query(Character).all()
    paginator = Paginator(post_list, 5)
    try:
        posts = paginator.page(page)
    except PageNotAnInteger:
        posts = paginator.page(1)
    except EmptyPage:
        posts = paginator.page(paginator.num_pages)
    return render_template('correspondents.html', posts=posts, login_session=login_session)


@app.route('/articles/')
@app.route('/articles')
def articles():
    return redirect(url_for('view', page=1))


@app.route('/articles/<int:page>', methods=['GET'])
def view(page):
    post_list = session.query(BlogEntry).all()
    paginator = Paginator(post_list, 5)
    try:
        posts = paginator.page(page)
    except PageNotAnInteger:
        posts = paginator.page(1)
    except EmptyPage:
        posts = paginator.page(paginator.num_pages)
    return render_template('articles.html', posts=posts,
                           login_session=login_session)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if session.query(User).filter_by(
                username=request.form['username']).all():
            flash('Username Already Exists')
            return render_template('register.html')
        if session.query(User).filter_by(
                email=request.form['email']).all():
            flash('Email already in use.')
            return render_template('register.html')
        else:
            newUser = User(username=request.form['username'],
                           email=request.form['email'])
            newUser.hash_password(request.form['password'])
            session.add(newUser)
            flash('Registered!')
            session.commit()
            return redirect(url_for('home'))
    else:
        return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session['state'] = state
    users = session.query(User).all()
    if request.method == 'POST':
        user = request.form['username']
        password = request.form['password']
        users = session.query(User).all
        if verify_password(user, password):
            login_session['username'] = user
            return redirect(url_for('home', login_session=login_session))
        else:
            flash('Wrong Credentials, friend.')
            return render_template('login.html', STATE=state, users=users)
    else:
        return render_template('login.html', STATE=state, users=users)


@app.route('/logout')
def logout():
    if 'username' in login_session:
        del login_session['username']
        del login_session['state']
        flash("You have successfully logged out.")
        return redirect(url_for('home'))
    else:
        flash("You aren't logged in.")
        return redirect(url_for('home'))


@app.route('/<int:user_id>/newpost', methods=["GET", "POST"])
def newPost(user_id):
    currentuser = session.query(User).filter_by(id=user_id).one()
    allUserChars = session.query(Character).filter_by(
        user_id=currentuser.id).all()
    if 'username' not in login_session or \
            currentuser.username != login_session['username']:
        flash('Sorry, but that is not your profile!')
        return redirect(url_for('home'))
    if request.method == 'POST':
        newEntry = BlogEntry(
            title=request.form['title'],
            entry=request.form['entry'],
            author=request.form['author'],
            date=_get_date(),
            user_id=currentuser.id)
        session.add(newEntry)
        flash('New Entry Added!')
        session.commit()
        return redirect(url_for('home', currentuser=currentuser,
                                login_session=login_session))
    else:
        return render_template('newpost.html', currentuser=currentuser,
                               login_session=login_session, allUserChars=allUserChars)


@app.route('/<int:user_id>/newcharacter', methods=["GET", "POST"])
def newChar(user_id):
    currentuser = session.query(User).filter_by(id=user_id).one()
    if 'username' not in login_session or \
            currentuser.username != login_session['username']:
        flash('Sorry, but this is not your profile!')
        return redirect(url_for('home'))
    if request.method == 'POST':
        instance = ''.join(random.choice(string.ascii_uppercase + string.digits)
                           for x in range(32))
        newCharacter = Character(name=request.form['name'],
                                 race=request.form['race'],
                                 gender=request.form['sex'],
                                 image_url='static/user-imgs/' + currentuser.username + instance,
                                 image_name=currentuser.username + instance,
                                 faction=request.form['faction'],
                                 biography=request.form['biography'],
                                 user_id=currentuser.id,
                                 owner_name=currentuser.username)
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        # if user does not select file, browser also
        # submit a empty part without filename
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(
                app.config['UPLOAD_FOLDER'], currentuser.username + instance))
        session.add(newCharacter)
        flash('New Character Uploaded!')
        session.commit()
        return redirect(url_for('home', login_session=login_session))
    else:
        return render_template('newcharacter.html', currentuser=currentuser,
                               login_session=login_session)


@app.route('/correspondents/<string:user_name>/<int:char_id>/<string:char>', methods=["GET", "POST"])
def charProf(user_name, char_id, char):
    try:
        currentuser = session.query(User).filter_by(
            username=login_session['username']).one()
    except:
        currentuser = 'Guest'
    activeProfile = session.query(User).filter_by(username=user_name).one()
    activeCharacter = session.query(Character).filter_by(id=char_id).one()
    allProfileChars = session.query(
        Character).filter_by(owner_name=user_name).all()
    if request.method == 'POST':
        if currentuser == 'Guest' or currentuser.id != activeProfile.id:
            flash('Sorry, this is not your profile!')
            return redirect(url_for('home', login_session=login_session))
        else:
            session.delete(activeCharacter)
            flash('Character Sucessfully Deleted...')
            session.commit()
            return redirect(url_for('home', login_session=login_session))
    return render_template('charprofile.html', activeProfile=activeProfile,
                           activeCharacter=activeCharacter,
                           allProfileChars=allProfileChars,
                           login_session=login_session,
                           currentuser=currentuser)


@app.route('/correspondents/<string:user_name>/<string:char>/<int:char_id>/edit', methods=["GET", "POST"])
def editChar(user_name, char, char_id):
    try:
        currentuser = session.query(User).filter_by(
            username=login_session['username']).one()
    except:
        currentuser = 'Guest'
    activeProfile = session.query(User).filter_by(username=user_name).one()
    activeCharacter = session.query(Character).filter_by(id=char_id).one()
    allProfileChars = session.query(
        Character).filter_by(owner_name=user_name).all()
    if request.method == 'POST':
        instance = ''.join(random.choice(string.ascii_uppercase + string.digits))
        if currentuser == 'Guest' or currentuser.id != activeProfile.id:
            flash('Sorry, this is not your profile!')
            return redirect(url_for('home', login_session=login_session))
        else:
            if request.form['name']:
                activeCharacter.name=request.form['name']
            if request.form['sex']:
                activeCharacter.gender=request.form['sex']
            if request.form['faction']:
                activeCharacter.faction=request.form['faction']
            if request.form['biography']:
                activeCharacter.biography=request.form['biography']
            if request.form['race']:
                activeCharacter.race=request.form['race']
            session.add(activeCharacter)
            flash('Character Sucessfully Updated!')
            session.commit()
            return redirect(url_for('charProf', user_name=activeProfile.username,
            char_id=activeCharacter.id, char=activeCharacter.name, login_session=login_session))
    else:
        return render_template('editcharacter.html', activeProfile=activeProfile,
                               activeCharacter=activeCharacter,
                               allProfileChars=allProfileChars,
                               login_session=login_session,
                               currentuser = currentuser)

    # TO DO #

    # User Profile Edit
    # User Profile Guest View

    # Character Edit/Delete/Owner VIew
    # Blog ENtry Edit/DElete/OWnerview
    # Browse Character Factions
    # Search Blog Posts

    # End of App Code


if __name__ == '__main__':
    app.secret_key=secret_key
    app.debug=True
    app.run(host='0.0.0.0', port=8000)
