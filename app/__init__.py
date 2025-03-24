from flask import Flask
import logging

from flask_cors import CORS
from flask_restx import Api, Resource
from .config import Config
from .routes import ns as routes_ns
from .services import init_services
#from .services import redis_client, celery

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Initialize external services like Redis, SocketIO, etc.
    #init_services(app)
    api = Api(
        app,
        version="1.0",
        title="PROBER API",
        description="APIs of PROBER tool",
    )

    # Import routes within the app context to avoid circular imports
    with app.app_context():
        from . import routes
#        from . import tasks

    # Register namespaces (routes)
    api.add_namespace(routes_ns, path='/api')

    return app

# from flask import Flask
# from flask_cors import CORS
# from flask_sse import sse
# from flask_socketio import SocketIO
# from redis import Redis
# from celery import Celery
# import logging
# from flask_restx import Api, Resource
# from .config import Config
#
# # Configure logging
# logging.basicConfig(level=logging.INFO)
# logger = logging.getLogger(__name__)
#
# socketio = SocketIO()
# redis_client = None
# celery = None
#
#
# def create_app():
#     app = Flask(__name__)
#     #api = Api(app, doc='/docs')  # Swagger UI available at /docs
#     app.config.from_object(Config)
#     #cve_ns = api.namespace('cve', description='CVE Processing Endpoints')
#
#     # Setup CORS
#     CORS(app)
#     socketio.init_app(app)
#
#     # Initialize Redis client
#     global redis_client
#     redis_client = Redis.from_url(app.config["REDIS_URL"])
#
#     # Register blueprint (ensure 'sse' is defined)
#     app.register_blueprint(sse, url_prefix='/stream')
#
#     # Configure Celery
#     global celery
#     celery = make_celery(app)
#
#     with app.app_context():
#         from . import routes  # Import routes after app context
#
#     return app
#
#
# def make_celery(app):
#     celery_instance = Celery(
#         app.import_name,
#         backend=app.config['CELERY_RESULT_BACKEND'],
#         broker=app.config['CELERY_BROKER_URL']
#     )
#     celery_instance.conf.update(app.config)
#     return celery_instance
