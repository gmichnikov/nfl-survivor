import os

# Set up database configuration
basedir = os.path.abspath(os.path.dirname(__file__))
# SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'app.db')
# SQLALCHEMY_DATABASE_URI = 'postgresql://mynewuser:mypassword@localhost/mynewdb'

# SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
# print("url: " + str(os.environ.get('DATABASE_URL')))

DATABASE_URL = os.environ.get('DATABASE_URL').replace("postgres://", "postgresql://", 1)
SQLALCHEMY_DATABASE_URI = DATABASE_URL


SECRET_KEY = os.environ.get('SECRET_KEY')
# print("key: " + str(os.environ.get('SECRET_KEY')))
