from flask_cors import CORS

from app import create_app, Config
from app.services import socketio

config = Config()

app = create_app()

if __name__ == "__main__":
    # Set the host and port for the app to listen on for docker only
    host = "0.0.0.0"  # Allows external access to the app (from Docker or outside)
    port = 5000  # The port your app will listen on
    socketio.run(app, host=host, port=port, allow_unsafe_werkzeug=True, debug=True)


