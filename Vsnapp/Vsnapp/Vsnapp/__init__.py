"""
The flask application package.
"""

from flask import Flask, request, jsonify, flash, redirect, url_for
from flask_login import LoginManager, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_sqlalchemy import *
from flask_jwt_extended import JWTManager
from flask import render_template
from datetime import datetime
from flask_socketio import SocketIO, send, emit, disconnect


db = SQLAlchemy()

def create_app():
    app = Flask(__name__)
    app.app_context().push()

    app.config['SECRET_KEY'] = 'secret-key-goes-here'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = 'False'
    app.config['JWT_TOKEN_LOCATION'] = ['headers', 'query_string']
    app.config['JWT_SECRET_KEY'] = 'super-secret'
    app.config['JWT_ALGORITHM'] = 'HS512'


    db.init_app(app)

    from flask_login import UserMixin

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    from .models import User
    from .models import Garage

    db.create_all()

    @login_manager.user_loader
    def load_user(user_id):
        # since the user_id is just the primary key of our user table, use it in the query for the user
        return User.query.get(int(user_id))

    # blueprint for auth routes in our app
    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)

    from .applic import applic as applic_blueprint
    app.register_blueprint(applic_blueprint)

    return app



app=create_app()
jwt = JWTManager(app)
socketio = SocketIO(app, logger=True, engineio_logger=True)

@socketio.on('connect')
def connect():
    print('Client connected')

@socketio.on('disconnect')
def disconnect():
    print('Client disconnected')


@socketio.on('message')
def handle_message(data):
    print('received message: ' + data)
    emit('message', data, broadcast=True)


#@socketio.on('message')
#def handle_my_custom_event(json, methods=['GET', 'POST']):
#    print('received my event: ' + str(json))
#    socketio.emit('message', json, callback=messageReceived)
#    #socketio.send( data = json, json = True,callback=messageReceived)

def messageReceived(methods=['GET', 'POST']):
    print('message was received!!!')

from .models import *

@app.route('/block_apriser', methods=['POST'])
def block_apriser():
    user = request.form.get('user')

    apriser = Apriser.query.filter_by(user=user).first()

    if not apriser:
        flash('NO user with this parametr')
        return redirect(url_for('auth.create'))
    
    if apriser.isBlocked == 1:
        apriser.isBlocked = 0
        db.session.commit()
    else:
        apriser.isBlocked = 1
        db.session.commit()
        socketio.emit('message', "{ \"from\" : \""+apriser.user+"\", \"to\" : \"\", \"comand\" : \"block\"}", broadcast=True)
    

    flash('Apriser Created.')
    return redirect(url_for('auth.create'))

@app.route('/block_garage', methods=['POST'])
def block_garage():
    user = request.form.get('user')

    apriser = Garage.query.filter_by(user=user).first()

    if not apriser:
        flash('NO user with this parametr')
        return redirect(url_for('auth.create_garage'))
    
    if apriser.isBlocked == 1:
        apriser.isBlocked = 0
    else:
        apriser.isBlocked = 1
        socketio.emit('message', "{ \"from\" : \""+apriser.user+"\", \"to\" : \"\", \"comand\" : \"block\"}", broadcast=True)
    db.session.commit()

    flash('Apriser Created.')
    return redirect(url_for('auth.create_garage'))