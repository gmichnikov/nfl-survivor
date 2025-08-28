from app import app
from app import routes  # Import routes here
from config import PORT

if __name__ == '__main__':
    app.run(debug=True, port=PORT)
