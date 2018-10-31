from flask import Flask, render_template, request, redirect, jsonify,
url_for, flash
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Restaurant, MenuItem, User
# Imports para State Token Antifraude
from flask import session as login_session
import random
import string
# Imports para funcao que trate do codigo recebido do metodo callback
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']

# Conectando ao banco de dados e criando uma sessao
engine = create_engine('sqlite:///restaurantmenu.db',
                       connect_args={'check_same_thread': False})
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Criando State Token para previnir requisicoes falsificadas
# Para um ataque de falsificacao de requisicao, o invasor teria que adivinhar o
# codigo gerado por essa funcao abaixo para fzr uma requisicao em nome do user
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    # Trocar token de curta duracao por um de longa duracao
    app_id = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = """https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token
            &client_id=%s&client_secret=%s
            &fb_exchange_token=%s""" % (app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # Usar token para pegar info do usuario pelo API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = """https://graph.facebook.com/v2.8/me?
    access_token=%s&fields=name,id,email""" % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # token guardado no session para deslogar mais tarde
    login_session['access_token'] = token

    # Obter foto de perfil
    url = """https://graph.facebook.com/v2.8/me/picture?
    access_token=%s&redirect=0&height=200&width=200""" % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # se este usuario ja existe no bd, nao precisa criar um novo
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Bem vindo, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += """ style = "width: 300px; height: 300px;border-radius: 150px;
    -webkit-border-radius: 150px;-moz-border-radius: 150px;"> """
    flash("Logado como %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    url = 'https://graph.facebook.com/%s/permissions' % facebook_id
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    del login_session['username']
    del login_session['picture']
    del login_session['user_id']
    del login_session['email']
    del login_session['facebook_id']
    return "voce foi deslogado"


@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
        if login_session['provider'] == 'facebook':
            fbdisconnect()

        flash("Voce foi deslogado com sucesso.")
        return redirect(url_for('showRestaurants'))
    else:
        flash("Voce nao esta logado para se deslogar.")
        return redirect(url_for('showRestaurants'))


@app.route('/gconnect', methods=['POST'])
def gconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('State Invalido'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    code = request.data
    try:
        # tentarei usar esse codigo avulso e troca-lo por um objeto
        # credentials que tenha o token de acesso para meu servidor
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Falha ao atualizar o codigo de autorizacao.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verificar se credentials tem um token de acesso valido
    access_token = credentials.access_token
    url = ("""https://www.googleapis.com/oauth2/v1/
    tokeninfo?access_token=%s""" % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])

    # se existe um erro no token, abortar
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'

    # verificar se o access token e usado para o usuario pretendido
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # verificar se ID do cliente e igual
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    # verificar se o usuario ja esta logado no sistema
    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Usuario ja esta conectado'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Guardar o access token na session
    login_session['provider'] = 'google'
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # API do Google para obter mais informacoes sobre o usuario
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # se este usuario ja existe no bd, nao precisa criar um novo
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Bem vindo, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += """ style = "width: 300px; height: 300px;border-radius: 150px;
    -webkit-border-radius: 150px;-moz-border-radius: 150px;"> """
    flash("voce agora esta logado como %s" % login_session['username'])
    print "done!"
    return output


# DESCONECTAR
@app.route('/gdisconnect')
def gdisconnect():
    # apneas desconectar usuario conectado
    access_token = login_session.get('access_token')
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: '
    print login_session.get('username')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    # print 'result is '
    # print result
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(
            json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# JSON APIs para ver informacoes detalhadas
@app.route('/restaurant/<int:restaurant_id>/menu/JSON')
def restaurantMenuJSON(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    items = session.query(MenuItem).filter_by(
        restaurant_id=restaurant_id).all()
    return jsonify(MenuItems=[i.serialize for i in items])


@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/JSON')
def menuItemJSON(restaurant_id, menu_id):
    Menu_Item = session.query(MenuItem).filter_by(
        id=menu_id, restaurant_id=restaurant_id)
    return jsonify(Menu_Item=Menu_Item.serialize)


@app.route('/restaurant/JSON')
def restaurantsJSON():
    restaurants = session.query(Restaurants).all()
    return jsonify(restaurants=[r.serialize for r in restaurants])


# Todos os restaurantes
@app.route('/')
@app.route('/restaurant/')
def showRestaurants():
    restaurants = session.query(Restaurant).order_by(asc(Restaurant.name))
    if 'username' not in login_session:
        return render_template(
            'publicrestaurants.html', restaurants=restaurants)
    else:
        return render_template(
            'restaurants.html', restaurants=restaurants)


# Criar novo restaurante
@app.route('/restaurant/new/', methods=['GET', 'POST'])
def newRestaurant():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newRestaurant = Restaurant(
            name=request.form['name'], user_id=login_session['user_id'])
        session.add(newRestaurant)
        flash('Novo restaurante %s criado' % newRestaurant.name)
        session.commit()
        return redirect(url_for('showRestaurants'))
    else:
        return render_template('newRestaurant.html')


# Editar restaurante
@app.route('/restaurant/<int:restaurant_id>/edit/', methods=['GET', 'POST'])
def editRestaurant(restaurant_id):
    if 'username' not in login_session:
        return redirect('/login')
    editedRestaurant = session.query(
        Restaurant).filter_by(id=restaurant_id).one()
    if request.method == 'POST':
        if request.form['name']:
            editedRestaurant.name = request.form['name']
            flash('Editado com Sucesso %s' % editedRestaurant.name)
            return redirect(url_for('showRestaurants'))
    else:
        return render_template(
            'editRestaurant.html', restaurant=editedRestaurant)


# Deletar restaurante
@app.route('/restaurant/<int:restaurant_id>/delete/', methods=['GET', 'POST'])
def deleteRestaurant(restaurant_id):
    restaurantToDelete = session.query(
        Restaurant).filter_by(id=restaurant_id).one()
    if 'username' not in login_session:
        return redirect('/login')
    if restaurantToDelete.user_id != login_session['user_id']:
        return """<script>function myFunction() {
        alert('Voce nao esta autorizado a deletar este restaurante.
        Favor criar seu proprio restaurante');}
        </script><body onload='myFunction()''>"""
    if request.method == 'POST':
        session.delete(restaurantToDelete)
        flash('%s Deletado com sucesso' % restaurantToDelete.name)
        session.commit()
        return redirect(url_for(
            'showRestaurants', restaurant_id=restaurant_id))
    else:
        return render_template(
            'deleteRestaurant.html', restaurant=restaurantToDelete)


# Mostrar menu de um restaurante
@app.route('/restaurant/<int:restaurant_id>/')
@app.route('/restaurant/<int:restaurant_id>/menu/')
def showMenu(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    creator = getUserInfo(restaurant.user_id)
    items = session.query(
        MenuItem).filter_by(restaurant_id=restaurant_id).all()
    if 'username' not in login_session or
    creator.id != login_session['user_id']:
        return render_template(
            'publicmenu.html', items=items,
            restaurant=restaurant, creator=creator)
    else:
        return render_template(
            'menu.html', items=items, restaurant=restaurant, creator=creator)


# Criar novo item de menu
@app.route("""/restaurant/<int:restaurant_id>/
menu/new/""", methods=['GET', 'POST'])
def newMenuItem(restaurant_id):
    if 'username' not in login_session:
        return redirect('/login')
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    if request.method == 'POST':
        newItem = MenuItem(name=request.form['name'],
                           description=request.form['description'],
                           price=request.form['price'],
                           course=request.form['course'],
                           restaurant_id=restaurant_id,
                           user_id=restaurant.user_id)
        session.add(newItem)
        session.commit()
        flash('Item de Menu %s criado com sucesso' % (newItem.name))
        return redirect(url_for('showMenu', restaurant_id=restaurant_id))
    else:
        return render_template('newmenuitem.html', restaurant_id=restaurant_id)


# Editar item
@app.route("""/restaurant/<int:restaurant_id>/menu/
<int:menu_id>/edit""", methods=['GET', 'POST'])
def editMenuItem(restaurant_id, menu_id):
    if 'username' not in login_session:
        return redirect('/login')
    editedItem = session.query(MenuItem).filter_by(id=menu_id).one()
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['price']:
            editedItem.price = request.form['price']
        if request.form['course']:
            editedItem.course = request.form['course']
        session.add(editedItem)
        session.commit()
        flash('Item de menu editado com sucesso')
        return redirect(url_for('showMenu', restaurant_id=restaurant_id))
    else:
        return render_template('editmenuitem.html',
                               restaurant_id=restaurant_id,
                               menu_id=menu_id,
                               item=editedItem)


# Deletar item
@app.route("""/restaurant/<int:restaurant_id>/menu/
<int:menu_id>/delete""", methods=['GET', 'POST'])
def deleteMenuItem(restaurant_id, menu_id):
    if 'username' not in login_session:
        return redirect('/login')
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    itemToDelete = session.query(MenuItem).filter_by(id=menu_id).one()
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('Item de menu deletado com sucesso')
        return redirect(url_for('showMenu', restaurant_id=restaurant_id))
    else:
        return render_template('deletemenuitem.html', item=itemToDelete)


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


def createUser(login_session):
    newUser = User(name=login_session['username'],
                   email=login_session['email'],
                   picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
