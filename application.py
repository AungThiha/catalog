import os
import random
import string
import httplib2
import json
import requests
from flask import Flask, render_template, request, redirect, jsonify, url_for, flash, \
    session as login_session, make_response, send_from_directory
from oauth2client.client import flow_from_clientsecrets, FlowExchangeError
from sqlalchemy import create_engine, desc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item, User
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Connect to Database and create database session
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
db = DBSession()

ALLOWED_EXT = set(['png', 'jpg', 'jpeg'])
app.config['UPLOAD_FOLDER'] = 'uploads'


def get_extension(f):
    if f and '.' in f.filename:
        file_ext = f.filename.rsplit('.', 1)[1]
        if file_ext in ALLOWED_EXT:
            return file_ext


@app.route('/uploads/<filename>')
def uploaded_photo(filename):
    filename = secure_filename(filename)
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/')
def show_home():
    categories = db.query(Category).all()
    print categories[8]
    items = db.query(Item).order_by(desc(Item.id)).all()
    if 'username' in login_session:
        logged_in = True
    else:
        logged_in = False
    return render_template('home.html', categories=categories, items=items, logged_in=logged_in, homepage=True)


@app.route('/catalog/<int:category_id>/')
def show_catalog(category_id):
    categories = db.query(Category).all()
    category = db.query(Category).filter_by(id=category_id).one()
    items = db.query(Item).filter_by(category_id=category_id).order_by(desc(Item.id)).all()
    if 'username' in login_session:
        logged_in = True
    else:
        logged_in = False
    return render_template('show_catalog.html', categories=categories, category=category, items=items, logged_in=logged_in)


@app.route('/catalog/<int:category_id>.json')
def show_catalog_json(category_id):
    return 'show catalog'


@app.route('/catalog/new', methods=['POST','GET'])
def add_item():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        category_id = request.form['category_id']
        name = request.form['name']
        if name:
            item = Item(name=name, description=request.form['description'],
                        category_id=category_id, user_id=login_session['user_id'])
            db.add(item)
            db.commit()
            f = request.files['photo']
            extension = get_extension(f)
            print f.filename
            if extension:
                filename = str(item.id) + '.' + extension
                f.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                item.photo = filename
                db.add(item)
                db.commit()
            flash("New item %s Successfully Added" % item.name)
            return redirect(url_for('show_catalog', category_id=category_id))
        flash("Name cannot be empty!")
    categories = db.query(Category).all()
    if request.args.get('category_id'):
        category = db.query(Category).filter_by(id=request.args.get('category_id')).one()
    else:
        category = None
    return render_template('add_item.html', categories=categories, category=category, logged_in=True)


@app.route('/catalog/<int:category_id>/<int:item_id>/')
def show_item(category_id, item_id):
    return 'show item'


@app.route('/catalog/<int:category_id>/<int:item_id>/edit')
def edit_item(category_id, item_id):
    return 'edit item'


@app.route('/catalog/<int:category_id>/<int:item_id>/delete')
def delete_item(category_id, item_id):
    return 'delete item'


# Create a state token to prevent request forgery.
# Store it in the session for later validation.
@app.route('/login')
def show_login():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['credentials'] = access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['provider'] = 'google'
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    user_id = get_user_id(login_session['email'])
    if not user_id:
        user_id = create_user(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += '" style = "width: 300px; height: 300px;' \
              'border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    web = json.loads(open('fb_client_secrets.json', 'r').read())['web']
    app_id = web['app_id']
    app_secret = web['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # User toekn to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.4/me"
    # strip expire tag from access token
    token = result.split("&")[0]
    url = 'https://graph.facebook.com/v2.4/me?%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout, let's strip out the information before the equals sign in our token
    stored_token = token.split("=")[1]
    login_session['access_token'] = stored_token

    # Get user picture
    url = 'https://graph.facebook.com/v2.4/me/picture?%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = get_user_id(login_session['email'])
    if not user_id:
        user_id = create_user(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += '" style="width: 300px; height: 300px;border-radius: 150px;' \
              '-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output

def gdisconnect():
    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(
            json.dumps("Current user not connected."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = ('https://accounts.google.com/o/oauth2/revoke?token=%s'
           % credentials)
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] != '200':
        response = make_response(
            json.dumps("Failed to revoke for given user."), 400)
        response.headers['Content-Type'] = 'application/json'
        return response

def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id,access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


# Disconnect based on provider
@app.route('/logout')
def logout():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['credentials']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('show_home'))
    else:
        flash("You were not logged in")
        return redirect(url_for('show_home'))


def get_user_id(email):
    try:
        user = db.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


def get_user(user_id):
    user = db.query(User).filter_by(id=user_id).one()
    return user


def create_user(login_session):
    new_user = User(name=login_session['username'],
                    email=login_session['email'],
                    picture=login_session['picture'])
    db.add(new_user)
    db.commit()
    user = db.query(User).filter_by(email=login_session['email']).one()
    return user.id


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='', port=8080)
