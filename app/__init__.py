from flask import Flask
from flask_migrate import Migrate
from dotenv import load_dotenv
load_dotenv()


app = Flask(__name__)
app.config.from_object('config')
# print("app config in init")

# from app import routes  # Import routes after creating the app object to avoid circular imports

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy(app)
migrate = Migrate(app, db)

from flask_login import LoginManager

login_manager = LoginManager(app)
login_manager.login_view = 'login'
