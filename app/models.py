from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

from app import db

from werkzeug.security import generate_password_hash, check_password_hash

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True)
    password_hash = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Pick(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    week = db.Column(db.Integer)
    team = db.Column(db.String(64))
    is_correct = db.Column(db.Boolean)

class WeeklyResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    week = db.Column(db.Integer)
    team = db.Column(db.String(64))
    result = db.Column(db.String(64))  # Can be 'win', 'lose', 'tie', 'did not play'
