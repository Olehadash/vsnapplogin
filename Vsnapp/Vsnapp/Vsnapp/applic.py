from flask import Blueprint, render_template, redirect, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from .models import *
from . import db
from flask_login import UserMixin
from flask_login import login_user, logout_user, login_required
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, get_raw_jwt
from sqlalchemy import or_

applic = Blueprint('applic', __name__)

@applic.route('/login_app', methods=['POST'])
def login_app_post():

    #content = request.get_json()

    login = request.form.get('login')
    #password = request.form.get('password')
    apriser = Apriser.query.filter_by(user=login).first()

    if not apriser:
        return jsonify(msg = "Logon Error. "), 401
    if apriser.isBlocked == 1:
        return jsonify(msg = "User Blocked "), 401

    #if not apriser.password == password:
    #    return jsonify(msg = "Password Error. "), 401

    return jsonify(apriser.serialize), 200

@applic.route('/login_garage_app', methods=['POST'])
def login_garage_app():

    login = request.form.get('login')
    password = request.form.get('password')
    #content = request.get_json()

    #login = content['login']
    garage = Garage.query.filter_by(user=login).first()

    if not garage:
        return jsonify(msg = "Logon Error. "), 401

    if not garage.password == password:
        return jsonify(msg = "Password Error. "), 401

    if garage.isBlocked == 1:
        return jsonify(msg = "User Blocked "), 401

    return jsonify(data = garage.serialize), 200

@applic.route('/get_garage_app', methods=['GET'])
def get_garage_app():
    garages = Garage.query.all()
    return jsonify(data = [i.serialize for i in garages]),200

@applic.route('/get_apriser_app', methods=['GET'])
def get_apriser_app():
    apris = Apriser.query.all()
    return jsonify(data = [i.serialize for i in apris]),200

@applic.route('/busy_garage_app', methods=['POST'])
def busy_garage_app():

    #content = request.get_json()

    login = request.form.get('login')
    garage = Apriser.query.filter_by(user=login).first()

    if not garage:
        return "Is no garage with user = " + login

    return jsonify(msg = garage.isBusy)

@applic.route('/setbusy_garage_app', methods=['POST'])
def setbusy_garage_app():

    #content = request.get_json()

    login = request.form.get('login')
    isbusy = request.form.get('isbusy')
    garage = Apriser.query.filter_by(user=login).first()
    arage.isBusy = isbusy

    db.session.commit()

    return garage.isBusy

