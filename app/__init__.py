from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

db = SQLAlchemy()
login_manager = LoginManager()


def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'your_secret_key'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'login'
    login_manager.login_message_category = 'info'

    from .models import User  # Импортируйте модель User
    with app.app_context():
        # Удаление всех записей в таблице пользователей
        db.session.query(User).delete()
        db.session.commit()

    from .routes import main
    app.register_blueprint(main)

    return app
