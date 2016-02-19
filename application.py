# import general
import os
import datetime
import random
import string
import httplib2
import json
import requests
from werkzeug.utils import secure_filename
from functools import wraps

# import flask
from flask import Flask, render_template, request, \
    redirect, jsonify, url_for, flash, \
    session, make_response, send_from_directory

# import oauth2
from oauth2client.client import flow_from_clientsecrets, FlowExchangeError

# csrf protection
from flask.ext.seasurf import SeaSurf

# import database stuffs
from sqlalchemy import create_engine, desc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item, User

# Connect to Database and create database session
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
db = DBSession()

# setup flask app
app = Flask(__name__)
app.secret_key = 'super_secret_key'

# csrf protection
csrf = SeaSurf()
csrf.init_app(app)

# setup upload files config
ALLOWED_EXT = ['png', 'jpg', 'jpeg']
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024


def get_extension(f):
    """
    get file extension from filename
    f:
      filename
    """
    if f and '.' in f.filename:
        file_ext = f.filename.rsplit('.', 1)[1]
        if file_ext in ALLOWED_EXT:
            return file_ext


@app.route('/uploads/<filename>')
def uploaded_photo(filename):
    """
    routes to get uploaded photo
    """
    filename = secure_filename(filename)
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('username'):
            return redirect(url_for('show_login'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def show_home():
    categories = db.query(Category).all()
    # with desc(Item.id), it return latest items on top
    items = db.query(Item).order_by(desc(Item.id)).all()
    if session.get('username'):
        logged_in = True
    else:
        logged_in = False
    # There's a category name within parentheses for each item and
    # these are shown only for homepage
    # The homepage variable is used to distinguish
    # between homepage and catalog page
    return render_template('home.html', categories=categories,
                           items=items, logged_in=logged_in, homepage=True)


@app.route('/catalog/<int:category_id>/')
def show_catalog(category_id):
    categories = db.query(Category).all()
    category = db.query(Category).filter_by(id=category_id).one()
    # with desc(Item.id), it return latest items on top
    items = db.query(Item).filter_by(category_id=category_id) \
        .order_by(desc(Item.id)).all()
    if session.get('username'):
        logged_in = True
    else:
        logged_in = False
    # category variable is used to define h1 for the item list
    return render_template('show_catalog.html', categories=categories,
                           category=category, items=items, logged_in=logged_in)


def get_categories_dict():
    categories = db.query(Category).all()
    dict_categories = []
    for c in categories:
        dict_c = c.serialize
        items = [
            i.serialize for i in
            db.query(Item).filter_by(category_id=c.id)
            .order_by(desc(Item.id)).all()
            ]
        dict_c['items'] = items
        dict_categories.append(dict_c)
    return dict_categories


@app.route('/catalog.json')
def show_home_json():
    categories = get_categories_dict()
    return jsonify(categories=categories)


@app.route('/catalog.xml')
def show_home_xml():
    categories = get_categories_dict()
    response = make_response(
        render_template('catalog.xml', categories=categories), 200)
    response.headers['Content-Type'] = 'application/xml'
    return response


@app.route('/catalog/new', methods=['POST', 'GET'])
@login_required
def add_item():
    name = None
    description = None
    category_id = '0'
    if request.method == 'POST':
        category_id = request.form['category_id']
        name = request.form['name'].strip()
        description = request.form['description']
        # validate name is not empty
        if name:
            item = Item(name=name, description=description,
                        category_id=category_id, user_id=session['user_id'])
            db.add(item)
            db.commit()
            f = request.files['photo']
            # validate file is with allowed extension and
            # get back the extension
            extension = get_extension(f)
            if extension:
                # photo named after item id to avoid overwriting
                # use timestamp in name to avoid caching headache after update
                filename = secure_filename(
                    str(item.id) + datetime.datetime.now().isoformat() +
                    '.' + extension)
                f.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                item.photo = filename
                db.add(item)
                db.commit()
            flash("New item %s Successfully Added" % item.name)
            return redirect(url_for('show_item',
                                    category_id=category_id, item_id=item.id))
        flash("Name cannot be empty!")
    categories = db.query(Category).all()
    if category_id == '0' and request.args.get('category_id'):
        category_id = request.args.get('category_id')
    item = {'name': name,
            'description': description,
            'category_id': int(category_id)}
    # if reload the page when validation for name is failed
    # so it needs to refill previous entered data when reload
    # for that, it use item variable
    return render_template('add_item.html', categories=categories,
                           item=item, logged_in=True)


@app.route('/catalog/<int:category_id>/<int:item_id>/')
def show_item(category_id, item_id):
    item = db.query(Item).filter_by(id=item_id, category_id=category_id).one()
    if session.get('username'):
        logged_in = True
        owner = item.user_id == session['user_id']
    else:
        logged_in = False
        owner = False
    return render_template('item.html', item=item,
                           owner=owner, logged_in=logged_in)


@app.route('/catalog/<int:category_id>/<int:item_id>/edit',
           methods=['POST', 'GET'])
@login_required
def edit_item(category_id, item_id):
    item = db.query(Item).filter_by(id=item_id, category_id=category_id).one()
    # protect CSRF attack
    if item.user_id != session['user_id']:
        return "<script> function myFunction() { " \
               "alert('You are not authorized to edit this item." \
               " Please create your own item" \
               " in order to do what you want.');" \
               "}</script>" \
               "<body onload='myFunction()'>"
    if request.method == 'POST':
        name = request.form['name']
        item.description = request.form['description']
        item.category_id = request.form['category_id']
        if name:
            item.name = name
            # value from 'Update Photo' checkbox
            # it updates the photo only if the checkbox is checked
            update_photo = request.form.getlist('update_photo')
            if update_photo:
                f = request.files['photo']
                extension = get_extension(f)
                filename = ''
                if extension:
                    # photo named after item id to avoid overwriting
                    # use timestamp in name to
                    # avoid caching headache after update
                    filename = secure_filename(
                        str(item.id) + datetime.datetime.now().isoformat() +
                        '.' + extension)
                    abs_file = os.path.join(app.config['UPLOAD_FOLDER'],
                                            filename)
                    f.save(abs_file)

                if item.photo:
                    abs_file = os.path.join(app.config['UPLOAD_FOLDER'],
                                            item.photo)
                    if os.path.exists(abs_file):
                        os.remove(abs_file)
                item.photo = filename
            db.add(item)
            db.commit()
            flash("%s Successfully Edited" % item.name)
            return redirect(url_for('show_item',
                                    category_id=category_id, item_id=item.id))
        flash("Name cannot be empty!")
    categories = db.query(Category).all()
    return render_template('edit_item.html', categories=categories,
                           item=item, logged_in=True)


@app.route('/catalog/<int:category_id>/<int:item_id>/delete', methods=['POST'])
@login_required
def delete_item(category_id, item_id):
    item = db.query(Item).filter_by(id=item_id, category_id=category_id).one()
    # protect CSRF attack
    if item.user_id != session['user_id']:
        return "<script> function myFunction() { " \
               "alert('You are not authorized to delete this item." \
               " Please create your own item" \
               " in order to do what you want.');" \
               "}</script>" \
               "<body onload='myFunction()'>"
    itemname = item.name
    filename = item.photo
    db.delete(item)
    db.commit()
    if filename:
        abs_file = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if os.path.exists(abs_file):
            os.remove(abs_file)
    flash('%s Successfully Deleted' % itemname)
    response = make_response(
            json.dumps('%s Successfully Deleted' % itemname), 200)
    response.headers['Content-Type'] = 'application/json'
    return response


# Create a state token to prevent request forgery.
# Store it in the session for later validation.
@app.route('/login')
def show_login():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    session['state'] = state
    # read gplus client id from client_secrets.json
    gplus_client_id = json.loads(
        open('client_secrets.json', 'r').read())['web']['client_id']
    # read fb app id from fb_client_secrets.json
    fb_app_id = json.loads(open('fb_client_secrets.json', 'r')
                           .read())['web']['app_id']
    return render_template(
        'login.html', STATE=state,
        gplus_client_id=gplus_client_id,
        fb_app_id=fb_app_id)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != session['state']:
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

    stored_credentials = session.get('credentials')
    stored_gplus_id = session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'),
            200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    session['credentials'] = access_token
    session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    session['provider'] = 'google'
    session['username'] = data['name']
    session['picture'] = data['picture']
    session['email'] = data['email']
    user_id = get_user_id(session['email'])
    if not user_id:
        user_id = create_user(session)
    session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += session['username']
    output += '!</h1>'
    output += '<img src="'
    output += session['picture']
    output += '" style = "width: 300px; height: 300px;' \
              'border-radius: 150px;' \
              '-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % session['username'])
    print "done!"
    return output


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    web = json.loads(open('fb_client_secrets.json', 'r').read())['web']
    app_id = web['app_id']
    app_secret = web['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (  # noqa
    # noqa
    app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # User toekn to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.4/me"
    # strip expire tag from access token
    token = result.split("&")[0]
    url = 'https://graph.facebook.com/v2.4/me?%s&fields=name,id,email' % token  # noqa
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    session['provider'] = 'facebook'
    session['username'] = data["name"]
    session['email'] = data["email"]
    session['facebook_id'] = data["id"]

    # The token must be stored in the session in order to properly logout,
    # let's strip out the information before the equals sign in our token
    stored_token = token.split("=")[1]
    session['access_token'] = stored_token

    # Get user picture
    url = 'https://graph.facebook.com/v2.4/me/picture?%s&redirect=0&height=200&width=200' % token  # noqa
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = get_user_id(session['email'])
    if not user_id:
        user_id = create_user(session)
    session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += session['username']

    output += '!</h1>'
    output += '<img src="'
    output += session['picture']
    output += '" style="width: 300px; height: 300px;border-radius: 150px;' \
              '-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % session['username'])
    return output


def gdisconnect():
    credentials = session.get('credentials')
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
    facebook_id = session['facebook_id']
    # The access token must me included to successfully logout
    access_token = session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % \
          (facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


# Disconnect based on provider
@app.route('/logout', methods=['POST'])
@login_required
def logout():
    if 'provider' in session:
        if session['provider'] == 'google':
            gdisconnect()
            del session['gplus_id']
            del session['credentials']
        if session['provider'] == 'facebook':
            fbdisconnect()
            del session['facebook_id']
        del session['username']
        del session['email']
        del session['picture']
        del session['user_id']
        del session['provider']
        flash("You have successfully been logged out.")
        response = make_response(
            json.dumps("You have successfully been logged out."), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        flash("You were not logged in")
        response = make_response(
            json.dumps("You were not logged in"), 401)
        response.headers['Content-Type'] = 'application/json'
        return response


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


# if __name__ == '__main__':
#     app.debug = True
#     app.run(host='', port=8080)
