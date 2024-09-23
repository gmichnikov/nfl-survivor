from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime, timedelta
from pytz import timezone
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey

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

    def __repr__(self):
        return f'<User {self.id} {self.username} with admin status {self.is_admin}>'

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


class Logs(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.now(timezone('US/Eastern')))
    user_id = db.Column(db.Integer, ForeignKey('user.id'))
    action_type = db.Column(db.String(50))
    description = db.Column(db.String(200))

class Spread(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    odds_id = db.Column(db.String(50), unique=True, nullable=False)
    update_time = db.Column(db.DateTime, nullable=False)
    game_time = db.Column(db.DateTime, nullable=False)
    home_team = db.Column(db.String(50), nullable=False)
    road_team = db.Column(db.String(50), nullable=False)
    home_team_spread = db.Column(db.Float, nullable=False)
    road_team_spread = db.Column(db.Float, nullable=False)
    week = db.Column(db.Integer, nullable=False)

class ResetCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    code = db.Column(db.String(64), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    used = db.Column(db.Boolean, default=False)

    def is_valid(self):
        return not self.used and (datetime.utcnow() - self.created_at) < timedelta(hours=24)
