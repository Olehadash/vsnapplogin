from flask import Blueprint, render_template, redirect, request, jsonify, abort, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from .models import *
from . import db
from flask_login import UserMixin
from flask_login import login_user, logout_user, login_required,  current_user
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, get_raw_jwt
from sqlalchemy import or_

auth = Blueprint('auth', __name__)

@auth.route('/')
@auth.route('/login')
def login():
    return render_template('login.html')

@auth.route('/gdpr')
def gdpr():
    return render_template('privasypolisy.html')

@auth.route('/login', methods=['POST'])
def login_post():
    
    email = request.form.get('email')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    user = User.query.filter_by(email=email).first()

    if not user:
        flash('Please check your login details and try again.')
        return redirect(url_for('auth.login'))

    if not (user.password == password):
        flash('Please check your password details and try again.')
        return redirect(url_for('auth.login'))

    login_user(user, remember=remember)
    return redirect(url_for('auth.create'))

@auth.route('/create')
@login_required
def create():
    if current_user.is_authenticated:
         return render_template('create.html', aprisers = Apriser.query.all())
    else:
        return redirect(url_for('auth.login'))

@auth.route('/create_garage')
@login_required
def create_garage():
    if current_user.is_authenticated:
         return render_template('createGarage.html', aprisers = Garage.query.all())
    else:
        return redirect(url_for('auth.login'))

@auth.route('/create_garage', methods=['POST'])
def create_garage_post():
    id = request.form.get('id')
    name = request.form.get('name')
    surname = request.form.get('surname')
    phone = request.form.get('phone')
    email = request.form.get('email')
    passport = request.form.get('passport')
    user = request.form.get('user')
    password = request.form.get('password')

    garage = Garage.query.filter_by(user=user).first()

    if id!="":
        if garage:
            return flash("GArage with user name exist. Please rename it")

    garage = Garage.query.filter_by(id=id).first()

    if garage:
        if name!= "":
            garage.name= name
        if user!= "":
            garage.user= user
        if password!= "":
            garage.password= password
        if surname!= "":
            garage.surname= surname
        if phone!= "":
            garage.phone= phone
        if email!= "":
            garage.email= email
        if passport!= "":
            garage.passport= passport

        
        db.session.commit()

        flash('Existing Created updated.')
        return redirect(url_for('auth.create_garage'))

    

    new_garage = Garage(name = name, user = user,  password = password, surname = surname, phone = phone, email= email, passport = passport)
    db.session.add(new_garage)
    db.session.commit()
    flash('Garage Created.')
    return redirect(url_for('auth.create_garage'))
    

@auth.route('/create_apriser', methods=['POST'])
def create_apriser():
    id = request.form.get('id')
    name = request.form.get('name')
    user = request.form.get('user')
    email = request.form.get('email')
    password = request.form.get('password')
    login = request.form.get('login')
    mobile = request.form.get('mobile')
    phone = request.form.get('phone')
    fax = request.form.get('fax')
    organization = request.form.get('organization')
    adres = request.form.get('adres')
    city = request.form.get('city')
    passpotid = request.form.get('passpotid')


    apriser = Apriser.query.filter_by(id=id).first()

    if id =="":
        app = Apriser.query.filter_by(user=user).first()
        if app :
            return flash("User with this name Exist! Please enter another name")

    if apriser:
        if user != "":
            apriser.user= user
        if name != "":
            apriser.name= name
        if email != "":
            apriser.email= email
        if password != "":
            apriser.password= password
        if login != "":
            apriser.login= login
        if mobile != "":
            apriser.mobile= mobile
        if phone != "":
            apriser.phone= phone
        if fax != "":
            apriser.fax= fax
        if organization != "":
            apriser.organization= organization
        if adres != "":
            apriser.adres= adres
        if city != "":
            apriser.city= city
        if passpotid != "":
            apriser.passpotid= passpotid
        db.session.commit()
        flash('Existing Apraiser updated.')
        return redirect(url_for('auth.create'))


    new_apriser = Apriser(name = name, user = user, email = email, password = password, login = login, mobile=mobile, phone=phone, fax = fax, organization=organization, adres = adres, city=city, passportid=passpotid)
    db.session.add(new_apriser)
    db.session.commit()
    flash('Apraiser Created.')
    return redirect(url_for('auth.create'))

@auth.route('/delete_apriser', methods=['POST'])
def delete_apriser():
    user = request.form.get('user')

    apriser = Apriser.query.filter_by(user=user).first()

    if not apriser:
        flash('NO user with this parametr')
        return redirect(url_for('auth.create'))
    
    db.session.delete(apriser)
    db.session.commit()

    flash('Apriser Created.')
    return redirect(url_for('auth.create'))

@auth.route('/block_apriser', methods=['POST'])
def block_apriser():
    user = request.form.get('user')

    apriser = Apriser.query.filter_by(user=user).first()

    if not apriser:
        flash('NO user with this parametr')
        return redirect(url_for('auth.create'))
    
    if apriser.isBlocked == 1:
        apriser.isBlocked = 0
    else:
        apriser.isBlocked = 1
    db.session.commit()

    flash('Apriser Created.')
    return redirect(url_for('auth.create'))



@auth.route('/delete_garage', methods=['POST'])
def delete_garage():
    user = request.form.get('user')

    apriser = Garage.query.filter_by(user=user).first()

    if not apriser:
        flash('NO user with this parametr')
        return redirect(url_for('auth.create_garage'))
    
    db.session.delete(apriser)
    db.session.commit()

    flash('Apriser Created.')
    return redirect(url_for('auth.create_garage'))

@auth.route('/block_garage', methods=['POST'])
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
    db.session.commit()

    flash('Apriser Created.')
    return redirect(url_for('auth.create_garage'))

@auth.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))