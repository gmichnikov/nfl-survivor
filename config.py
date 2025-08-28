import os

# Set up database configuration

DATABASE_URL = os.environ.get('DATABASE_URL').replace("postgres://", "postgresql://", 1)
SQLALCHEMY_DATABASE_URI = DATABASE_URL

PORT = int(os.environ.get('PORT', 5000))

SECRET_KEY = os.environ.get('SECRET_KEY')

ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME')