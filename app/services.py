from flask import Flask
from flask_cors import CORS
# from redis import Redis
from flask_socketio import SocketIO
# from celery import Celery
# from flask_sse import sse

# # Initialize services
# redis_client = None
socketio = SocketIO()
# celery = None


def make_celery(app: Flask):
    celery_instance = Celery(
        app.import_name,
        backend=app.config['CELERY_RESULT_BACKEND'],
        broker=app.config['CELERY_BROKER_URL']
    )
    celery_instance.conf.update(app.config)
    return celery_instance


def init_services(app: Flask):
    # Setup CORS
    CORS(app)
    socketio.init_app(app)

    # Initialize Redis client
    global redis_client
    redis_client = Redis.from_url(app.config["REDIS_URL"])

    # Register blueprint (ensure 'sse' is defined)
    app.register_blueprint(sse, url_prefix='/stream')

    # Configure Celery
    global celery
    celery = make_celery(app)




