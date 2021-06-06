"""
This script runs the Vsnapp application using a development server.
"""

from os import environ
from Vsnapp import app, socketio 

if __name__ == '__main__':
    HOST = environ.get('SERVER_HOST', 'localhost')
    #app.run(HOST, 5555)
    socketio.run(app, host = HOST, port = 8080)

