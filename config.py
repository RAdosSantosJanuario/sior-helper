from flask import Flask
from flask_wtf import CSRFProtect
import os
import markdown2
import logging
import redis
from Models import db

app = Flask(__name__)
redis_client = redis.Redis(host='redis', password=os.getenv('REDIS_PASSWORD'))

app_logger = logging.getLogger('Flask')
app_logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
app_logger.addHandler(handler)
app_logger.propagate = False

def markdown_to_html(markdown_text):
    """Convert Markdown text to HTML"""
    return markdown2.markdown(str(markdown_text))

def initialize_app():
    app_logger.info("Creating database")
    with app.app_context():
        db.create_all()
    
    app_logger.info("Testing Redis connection.")
    test_redis_connection()
    
    app_logger.info("Initialization complete.")

def test_redis_connection():
    try:
        response = redis_client.ping()
        if response:
            app_logger.info("Connected to Redis successfully.")
        else:
            app_logger.error("Failed to connect to Redis.")
    except Exception as e:
        app_logger.error(f"Redis connection error: {str(e)}")

def configure_app():
    app.config.update(
        CELERY_BROKER_URL=os.environ.get('CELERY_BROKER_URL'),
        result_backend=os.environ.get('CELERY_RESULT_BACKEND')
    )
    username = os.getenv('MYSQL_USER')
    password = os.getenv('MYSQL_PASSWORD')
    hostname = os.getenv('MYSQL_HOST')
    database = os.getenv('MYSQL_DATABASE')
    port = os.getenv('MYSQL_PORT')
    app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://{username}:{password}@{hostname}:{port}/{database}'
    db.init_app(app)
    
    app.secret_key = os.environ.get('APP_SECRET_KEY')
    app.config['SECRET_KEY'] = os.environ.get('APP_SECRET_KEY')
    if not app.config['SECRET_KEY'] or not app.secret_key:
        print("Error: SECRET_KEY is not set!")
        exit(-1)
        
    app.config['SECURITY_PASSWORD_SALT'] = os.environ.get('SECURITY_PASSWORD_SALT')
    if not app.config['SECURITY_PASSWORD_SALT']:
        print("Error: SECURITY_PASSWORD_SALT is not set!")
        exit(-2)
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['RECAPTCHA_PUBLIC_KEY'] = os.environ.get('RECAPTCHA_PUBLIC_KEY')
    app.config['RECAPTCHA_PRIVATE_KEY'] = os.environ.get('RECAPTCHA_PRIVATE_KEY')
    app.config['SENDGRID_API_KEY'] = os.environ.get('SENDGRID_API_KEY')
    app.config['SENDGRID_FROM_EMAIL'] = os.environ.get('SENDGRID_FROM_EMAIL')
    
    app.jinja_env.filters['markdown'] = markdown_to_html

    
    csrf = CSRFProtect(app)

    return app
