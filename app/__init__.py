from flask import Flask
from dotenv import load_dotenv
load_dotenv()


app = Flask(__name__)
app.config.from_object('config')
# print("app config in init")

# from app import routes  # Import routes after creating the app object to avoid circular imports

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy(app)

from flask_login import LoginManager

login = LoginManager(app)
login.login_view = 'login'
