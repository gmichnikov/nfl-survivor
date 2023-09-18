from app import app
from app import routes  # Import routes here
from dotenv import load_dotenv
load_dotenv()

if __name__ == '__main__':
    app.run(debug=True)
