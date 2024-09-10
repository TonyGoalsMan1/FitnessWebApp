from app import app, db, User
from werkzeug.security import generate_password_hash

# Создаем контекст приложения
with app.app_context():
    # Создаем объект пользователя
    admin = User(
        username='admin1',
        email='admirrn@example.com',
        password=generate_password_hash('admin1'),
        role='admin'
    )

    # Добавляем пользователя в сессию и сохраняем
    db.session.add(admin)
    db.session.commit()


