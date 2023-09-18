import os

# Set up database configuration
basedir = os.path.abspath(os.path.dirname(__file__))
# SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'app.db')
SQLALCHEMY_DATABASE_URI = 'postgresql://mynewuser:mypassword@localhost/mynewdb'


SECRET_KEY = os.environ.get('SECRET_KEY')
