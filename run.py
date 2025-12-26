# [CRITICAL] This must be the very first line
import eventlet
eventlet.monkey_patch()

from app import create_app
from app.extensions import socketio

app = create_app()

if __name__ == '__main__':
    # This block only runs on LOCALHOST
    # We remove debug=True here because debug mode is now controlled 
    # by the environment variable in app/__init__.py
    socketio.run(app, port=7000)