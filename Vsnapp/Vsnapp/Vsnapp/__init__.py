"""
The flask application package.
"""

from flask import Flask, request, jsonify
from flask_login import LoginManager, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_sqlalchemy import *
from flask_jwt_extended import JWTManager
from flask import render_template
from datetime import datetime

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
