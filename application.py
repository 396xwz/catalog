from flask import Flask, render_template, request, redirect,jsonify, url_for, flash
app = Flask(__name__)

from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database import Base, Categories, Items, User
from flask import session as login_session
import random, string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
from register import *
import json
from flask import make_response

from flask import abort as flask_abort, request
from werkzeug.exceptions import default_exceptions, HTTPException
from flask.exceptions import JSONHTTPException

import requests
import os

CLIENT_ID = json.loads(
  open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME= "Catalog App"


#Connect to Database and create database session
engine = create_engine('sqlite:///categoryitem.db', echo=False)
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()
# CSRF Protection
@app.before_request
def csrf_protect():
    if request.path != "/gconnect":
     print ""
    elif request.path != "/fbconnect":
       if request.method == "POST":
        token = login_session.pop('_csrf_token', None)
        if not token or token != request.form.get('_csrf_token'):
            abort(403)
def generateRandomString(length = 32):
     return ''.join(random.choice(string.letters + string.digits) for x in range(length))

def generate_csrf_token():
    if '_csrf_token' not in login_session:
        login_session['_csrf_token'] = generateRandomString()
        # login_session['_csrf_token'] = login_session['state']
    return login_session['_csrf_token']

#signup user
@app.route('/register', methods=['GET', 'POST'])
def register():
    username_error = ''
    password_error = ''
    verify_error = ''
    email_error = ''
    if request.method == 'POST':
        signupError = False
        newUsername = request.form['username']
        newEmail = request.form['email']

        if not verify_username(newUsername):
            username_error = "That's not a valid username."
            signupError = True
        if not verify_email(newEmail):
            email_error = "That's not a valid email."
            signupError = True

        if signupError:
            return render_template('register.html', username_error = username_error,
                                                    email_error = email_error)
        else:
            newUser = User(username = newUsername,
                                email = newEmail)
            session.add(newUser)
            #set cookie here
            session.commit()
            return redirect('/')
    else:
        return render_template('register.html', username_error = username_error,
                                                    email_error = email_error)

#Create anti-forgery state token
@app.route('/login')
def showLogin():
  state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
  login_session['state'] = state
  return render_template('login.html', STATE = state)

@app.route('/fbconnect', methods=['POST'])
def fbconnect():
  if request.args.get('state') != login_session['state']:
    response = make_response(json.dumps('Invalid state parameter.'), 401)
    response.headers['Content-Type'] = 'application/json'
    return response
  access_token = request.data
  print "access token received %s "% access_token

  #Exchange client token for long-lived server-side token
  app_id = json.loads(open('fb_client_secrets.json', 'r').read())['web']['app_id']
  app_secret = json.loads(open('fb_client_secrets.json', 'r').read())['web']['app_secret']
  url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (app_id,app_secret,access_token)
  h = httplib2.Http()
  result = h.request(url, 'GET')[1]

  #Use token to get user info from API 
  userinfo_url =  "https://graph.facebook.com/v2.2/me"
  #strip expire tag from access token
  token = result.split("&")[0]
  
  url = 'https://graph.facebook.com/v2.3/me?%s' % token
  h = httplib2.Http()
  result = h.request(url, 'GET')[1]
#  print "url sent for API access:%s"% url
#  print "API JSON result: %s" % result
  data = json.loads(result)
  login_session['provider'] = 'facebook'
  login_session['username'] = data["name"]
  login_session['email'] = data["id"] 
  login_session['facebook_id'] = data["id"]
  

  #Get user picture
  url = 'https://graph.facebook.com/v2.2/me/picture?%s&redirect=0&height=200&width=200' % token
  h = httplib2.Http()
  result = h.request(url, 'GET')[1]
  data = json.loads(result)

  login_session['picture'] = data["data"]["url"]
  
  # see if user exists
  user_id = getUserID(login_session['email'])
  if not user_id:
    user_id = createUser(login_session)
  login_session['user_id'] = user_id
    
  output = ''
  output +='<h1>Welcome, '
  output += login_session['username']

  output += '!</h1>'
  output += '<img src="'
  output += login_session['picture']
  output +=' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '


  flash ("Now logged in as %s" % login_session['username'])
  return output

@app.route('/fbdisconnect')
def fbdisconnect():
  facebook_id = login_session['facebook_id']
  url = 'https://graph.facebook.com/%s/permissions' % facebook_id
  h = httplib2.Http()
  result = h.request(url, 'DELETE')[1] 
  return "you have been logged out"

@app.route('/gconnect', methods=['POST'])
def gconnect():
#Validate state token 
  if request.args.get('state') != login_session['state']:
    response = make_response(json.dumps('Invalid state parameter.'), 401)
    response.headers['Content-Type'] = 'application/json'
    return response
  #Obtain authorization code
  code = request.data
  
  try:
    # Upgrade the authorization code into a credentials object
    oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
    oauth_flow.redirect_uri = 'postmessage'
    credentials = oauth_flow.step2_exchange(code)
  except FlowExchangeError:
    response = make_response(json.dumps('Failed to upgrade the authorization code.'), 401)
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
  if result['issued_to'] != CLIENT_ID:
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
  login_session['credentials'] = credentials
  login_session['gplus_id'] = gplus_id
 
  
  #Get user info
  userinfo_url =  "https://www.googleapis.com/oauth2/v1/userinfo"
  params = {'access_token': credentials.access_token, 'alt':'json'}
  answer = requests.get(userinfo_url, params=params)
  
  data = answer.json()

  login_session['username'] = data['name']
  login_session['picture'] = data['picture']
  login_session['email'] = data['email']
  #ADD PROVIDER TO LOGIN SESSION
  login_session['provider'] = 'google'
 
  #see if user exists, if it doesn't make a new one
  user_id = getUserID(data["email"])
  if not user_id:
    user_id = createUser(login_session)
  login_session['user_id'] = user_id


  output = ''
  output +='<h1>Welcome, '
  output += login_session['username']
  output += '!</h1>'
  output += '<img src="'
  output += login_session['picture']
  output +=' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
  flash("you are now logged in as %s"%login_session['username'])
  print "done!"
  return output

#User Helper Functions
def createUser(login_session):
  newUser = User(username = login_session['username'], email = login_session['email'])
  session.add(newUser)
  session.commit()
  user = session.query(User).filter_by(email = login_session['email']).one()
  print user
  return user.id

def getUserInfo(user_id):
  user = session.query(User).filter_by(id = user_id).one()
  return user

def getUserID(Email):
  try:
      user = session.query(User).filter_by(email = Email).one()
      print user.id
      return user.id
  except:
      return None

#DISCONNECT - Revoke a current user's token and reset their login_session
@app.route('/gdisconnect')
def gdisconnect():
  #Only disconnect a connected user.
  credentials = login_session.get('credentials')
  if credentials is None:
    response = make_response(json.dumps('Current user not connected.'),401)
    response.headers['Content-Type'] = 'application/json'
    return response 
  access_token = credentials.access_token
  url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
  h = httplib2.Http()
  result = h.request(url, 'GET')[0]
  if result['status'] != '200':
    # For whatever reason, the given token was invalid.
    response = make_response(json.dumps('Failed to revoke token for given user.', 400))
    response.headers['Content-Type'] = 'application/json'
    return response


#JSON APIs to view catalog item Information
@app.route('/catalog/<path:catalogName>/<path:itemName>/JSON')
def catalogItemJSON(catalogName, itemName):
    items = session.query(Items).filter_by(name=itemName, cata_name=catalogName).all()

    return jsonify(Items=[i.serialize for i in items])


#JSON APIs to view catalog items 
@app.route('/catalog/<path:catalogName>/JSON')
@app.route('/catalog/<path:catalogName>/items/JSON')
def catalogItemsJSON(catalogName):
    items = session.query(Items).filter_by(cata_name=catalogName).all()
    return jsonify(Items=[i.serialize for i in items])
#JSON API to view categories
@app.route('/catalog/JSON')
def catalogsJSON():
    cat = session.query(Categories).all()

    return jsonify(cat= [r.serialize for r in cat])


#Show all catalogs
@app.route('/')
@app.route('/catalog/')
def showcatalogs():
  cat = session.query(Categories).all()
  latest10Items = session.query(Items).order_by(Items.create_time.desc()).limit(10).all()
  if 'username' not in login_session:
    return render_template('publiccatalogs.html',
                            cat = cat,
	                    latest10Items = latest10Items)
  else:
    return render_template('catalogs.html', cat = cat, latest10Items = latest10Items)

#Create a new category
@app.route('/catagory/new/', methods=['GET','POST'])
def newCategory():
  if 'username' not in login_session:
    return redirect('/login')
  if request.method == 'POST':
      Name = request.form['name'] 
      
      User_id=login_session['user_id']
      
      newcategory = Categories(name = Name,
                        user_id = User_id)
                        

      session.add(newcategory)
      flash('New category %s Successfully Created' % newcategory.name)
      session.commit()
      return redirect(url_for('showcatalogs'))
  else:
      return render_template('newcatalog.html')

#Edit a catalog
@app.route('/catalog/<int:catalog_id>/edit/', methods = ['GET', 'POST'])
def editcatalog(catalog_id):
  editedcatalog = session.query(catalog).filter_by(id = catalog_id).one()
  if 'username' not in login_session:
    return redirect('/login')
  if editedcatalog.user_id != login_session['user_id']:
    return "<script>function myFunction() {alert('You are not authorized to edit this catalog. Please create your own catalog in order to edit.');}</script><body onload='myFunction()''>"
  if request.method == 'POST':
      if request.form['name']:
        editedcatalog.name = request.form['name']
        flash('catalog Successfully Edited %s' % editedcatalog.name)
        return redirect(url_for('showcatalogs'))
  else:
    return render_template('editcatalog.html', catalog = editedcatalog)


#Delete a catalog
@app.route('/catalog/<int:catalog_id>/delete/', methods = ['GET','POST'])
def deletecatalog(catalog_id):
  catalogToDelete = session.query(catalog).filter_by(id = catalog_id).one()
  print catalog_id
  print catalogToDelete
  if 'username' not in login_session:
    return redirect('/login')
  if catalogToDelete.user_id != login_session['user_id']:
    return "<script>function myFunction() {alert('You are not authorized to delete this catalog. Please create your own catalog in order to delete.');}</script><body onload='myFunction()''>"
  if request.method == 'POST':
    session.delete(catalogToDelete)
    flash('%s Successfully Deleted' % catalogToDelete.name)
    session.commit()
    return redirect(url_for('showcatalogs', catalog_id = catalog_id))
  else:
    return render_template('deletecatalog.html',catalog = catalogToDelete)

#Show a catalog items
@app.route('/catalog/<path:catalogName>/')
@app.route('/catalog/<path:catalogName>/items/')
def showCatalogItems(catalogName):
    categories = session.query(Categories).all()
    items = session.query(Items).filter_by(cata_name=catalogName).all()
    return render_template('catalogitem.html',
                            categories = categories,
                            catename = catalogName,
                            items = items)
#description of item
@app.route('/catalog/<path:catalogName>/<path:itemName>/')
def showItemDescription(itemName, catalogName):
    items = session.query(Items).filter_by(name=itemName, cata_name=catalogName).all()
    if len(items)==0:
        abort(404)
    else:
        item = items[0]
        return render_template('itemdescription.html', item = item)

#Add new item
@app.route('/catalog/<path:catalogName>/additem/', methods=['GET', 'POST'])
def addItem(catalogName):
    categories = session.query(Categories).filter_by(name = catalogName).all()
    
    if 'username' not in login_session:
     return redirect('/login')
    for ID in categories:
     if ID.user_id != login_session['user_id']:
       return "<script>function myFunction() {alert('You are not authorized to add items. Please create your own catalog in order to add items.');}</script><body onload='myFunction()''>"

    if catalogName not in [cat.name for cat in categories]:
        abort(404)
    if request.method == 'POST':
        newName = request.form['title']
        newDes = request.form['description']
        newCatName = request.form['category']
        newCat = session.query(Categories).filter_by(name=newCatName).one()
        newItem = Items(name = newName,
                        description = newDes,
                        category = newCat)
        session.add(newItem)
        session.commit()
        return redirect(url_for('showCatalogItems', catalogName=newCatName))
    else:
        return render_template('addItem.html', cataName=catalogName, categories=categories)
#Edit item
@app.route('/catalog/<path:catalogName>/<path:itemName>/edit/', methods=['GET', 'POST'])
def editItem(catalogName, itemName):
    
    categories = session.query(Categories).filter_by(name = catalogName).all()
    editedItems = session.query(Items).filter_by(name=itemName, cata_name=catalogName).all()
    if 'username' not in login_session:
     return redirect('/login')
    for ID in categories:
     if ID.user_id != login_session['user_id']:

      return "<script>function myFunction() {alert('You are not authorized to edit this item. Please create your own catalog in order to edit items.');}</script><body onload='myFunction()''>"

    if len(editedItems)==0:
        abort(404)
    editedItem = editedItems[0]
    if request.method == 'POST':
        newName = request.form['title']
        newDes = request.form['description']
        newCatName = request.form['category']
        newCat = session.query(Categories).filter_by(name=newCatName).one()
        editedItem.name = newName
        editedItem.description = newDes
        editedItem.category = newCat
        session.add(editedItem)
        session.commit()
        return redirect(url_for('showItemDescription', itemName=newName, catalogName=newCatName))
    else:
        return render_template('edititem.html', item = editedItem, categories=categories)
#Delete an item
@app.route('/catalog/<path:catalogName>/<path:itemName>/delete/', methods=['GET', 'POST'])
def deleteItem(itemName, catalogName):
    deletedItems = session.query(Items).filter_by(name=itemName, cata_name=catalogName).all()
    categories = session.query(Categories).filter_by(name = catalogName).all()
 
    if 'username' not in login_session:
     return redirect('/login')
    for ID in categories:
     if ID.user_id != login_session['user_id']:

      return "<script>function myFunction() {alert('You are not authorized to delete this item. Please create your own catalog in order to delete items.');}</script><body onload='myFunction()''>"

    if len(deletedItems)==0:
        abort(404)
    deletedItem = deletedItems[0]
    if request.method == 'POST':
        session.delete(deletedItem)
        session.commit()
        return redirect(url_for('showCatalogItems', catalogName=catalogName))
    else:
        return render_template('deleteitem.html', item= deletedItem)

#Edit catalog
@app.route('/catalog/<path:catalogName>/edit/', methods=['GET', 'POST'])
def editCatalog(catalogName):
    if 'username' not in login_session:
     return redirect('/login')

    editedCatalogs = session.query(Categories).filter_by(name=catalogName).all()
    for ID in editedCatalogs:
     if ID.user_id != login_session['user_id']:

      return "<script>function myFunction() {alert('You are not authorized to edit this catalog. Please create your own catalog in order to edit items.');}</script><body onload='myFunction()''>"
      
    if len(editedCatalogs)==0:
        abort(404)
    editedCatalog = editedCatalogs[0]
    itemsCatalog = session.query(Items).filter_by(cata_name=catalogName).all()
    if request.method == 'POST':
        newCatName = request.form['title']
        editedCatalog.name = newCatName
        session.add(editedCatalog)
        session.commit()
        for item in itemsCatalog:
            item.category = editedCatalog
            session.add(item)
            session.commit()
        return redirect(url_for('showCatalogItems', catalogName=newCatName))
    else:
        return render_template('editcatalog.html', catalog_name=catalogName)

#Delete an empty catalog
@app.route('/catalog/<path:catalogName>/delete/', methods=['GET', 'POST'])
def deleteCatalog(catalogName):
    deletedCats = session.query(Categories).filter_by(name=catalogName).all()
    if len(deletedCats)==0:
        abort(404)
    deletedCat = deletedCats[0]
    empty  = len(session.query(Items).filter_by(cata_name=deletedCat.name).all())
    if request.method == 'POST':
        session.delete(deletedCat)
        session.commit()
        return redirect(url_for('showcatalogs'))
    else:
        return render_template('deleteCatalog.html', catalog_name=catalogName, empty=empty)


#Disconnect based on provider
@app.route('/disconnect')
def disconnect():
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
    return redirect(url_for('showcatalogs'))
  else:
    flash("You were not logged in")
    return redirect(url_for('showcatalogs'))

# CSRF Protection
def abort(status_code, body=None, headers={}):
    """
    Content negiate the error response.

    """

    if 'text/html' in request.headers.get("Accept", ""):
        error_cls = HTTPException
    else:
        error_cls = JSONHTTPException

    class_name = error_cls.__name__
    bases = [error_cls]
    attributes = {'code': status_code}

    if status_code in default_exceptions:
        # Mixin the Werkzeug exception
        bases.insert(0, default_exceptions[status_code])

    error_cls = type(class_name, tuple(bases), attributes)
    flask_abort(make_response(error_cls(body), status_code, headers))


if __name__ == '__main__':
  app.secret_key = 'super_secret_key'
  app.jinja_env.globals['csrf_token'] = generate_csrf_token 
  app.debug = True
  app.run(host = '0.0.0.0', port = 8080)


