from flask_login import UserMixin
from Vsnapp import db
import datetime


class Apriser(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True, unique=True)
    name = db.Column(db.String(1000))
    user = db.Column(db.String(1000), unique=True)
    password = db.Column(db.String(1000))
    email = db.Column(db.String(100))
    login = db.Column(db.String(1000))
    mobile = db.Column(db.Integer)
    phone = db.Column(db.Integer)
    fax = db.Column(db.Integer)
    organization = db.Column(db.String(1000))
    adres = db.Column(db.String(1000))
    city = db.Column(db.String(1000))
    passportid = db.Column(db.Integer)
    isBusy = db.Column(db.Boolean)
    isBlocked = db.Column(db.Integer)

    def __repr__(self):
        return '<Apriser %r>' % self.username

    @property
    def serialize(self):
        return {
                'id' : self.id,
                'name' : self.name,
                'user' : self.user,
                'password' : self.password,
                'email' : self.email,
                'login' : self.login,
                'mobile' : self.mobile,
                'phone' : self.phone,
                'fax' : self.fax,
                'organization' : self.organization,
                'adres' : self.adres,
                'city' : self.city,
                'passportid' : self.city
            }


class Garage(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True, unique=True)
    name = db.Column(db.String(1000))
    user = db.Column(db.String(1000))
    isBusy = db.Column(db.Boolean, unique=False, nullable=False, default=False)
    password = db.Column(db.String(1000))
    isBlocked = db.Column(db.Integer)

    def __repr__(self):
        return '<Garage %r>' % self.name

    @property
    def serialize(self):
        return {
                'id' : self.id,
                'name' : self.name,
                'user' : self.user,
                'password' : self.password
            }


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True) # primary keys are required by SQLAlchemy
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))

    def __repr__(self):
        return '<User %r>' % self.username