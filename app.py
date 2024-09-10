from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime
from flask import render_template
from flask import Flask, request, jsonify, session, redirect, url_for, render_template
from functools import wraps
from flask import Flask, request, jsonify, session, redirect, url_for, render_template, flash
import os
import shutil
from datetime import datetime
from flask import current_app, jsonify
import paramiko
import logging
from flask import Flask, request, jsonify, make_response
import pandas as pd
from io import BytesIO
from flask import send_file
from flask import Flask, request, jsonify, make_response, send_file
from flask_sqlalchemy import SQLAlchemy
import pandas as pd
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from sqlalchemy import create_engine





# Настройка логирования
logging.basicConfig(level=logging.INFO)

app = Flask(__name__)
app.debug = True
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:/FlaskCourse/instance/fitness.db'
app.config['SECRET_KEY'] = 'your_secret_key'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

migrate = Migrate(app, db)

# Модель пользователя
class User(UserMixin,db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    registration_date = db.Column(db.DateTime, default=datetime.utcnow)
    age = db.Column(db.Integer)
    sex = db.Column(db.String(10))
    birth = db.Column(db.DateTime)
    weight = db.Column(db.Float)
    height = db.Column(db.Float)
    trainings = db.relationship('TrainingHistory', backref='user')
    meals = db.relationship('MealHistory', backref='user')
    trainers = db.relationship('UserTrainer', backref='user')
    role = db.Column(db.String(10))  # Например, 'user' или 'admin'
    pass
# Модель тренера
class Trainer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    trainer_name = db.Column(db.String(100))
    email = db.Column(db.String(120), unique=True, nullable=False)
    work_direction = db.Column(db.String(100))
    start_work = db.Column(db.String)  # Изменено на строковый тип

# Модель тренировки
class Training(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    training_name = db.Column(db.String(100))
    description = db.Column(db.Text)
    training_type = db.Column(db.String(50))
    level = db.Column(db.String(50))
    training_time = db.Column(db.Integer)  # В минутах
    equipment = db.Column(db.String(100))
    # Связь с историей тренировок
    history = db.relationship('TrainingHistory', backref='training')  # backref должен указывать на 'training'

# Модель истории тренировок
class TrainingHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    training_plan_id = db.Column(db.Integer, db.ForeignKey('training_plan.id'))
    progress_notes = db.Column(db.Text)  # Поле для заметок о прогрессе
    date = db.Column(db.DateTime, default=datetime.utcnow)
    training_id = db.Column(db.Integer, db.ForeignKey('training.id'))  # Убедитесь, что это поле существует

# Модель пищи
class Food(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    food_name = db.Column(db.String(100))
    calories = db.Column(db.Integer)
    composition = db.Column(db.Text)
    # Связь с историей пищи
    food_history = db.relationship('FoodHistory', backref='food')

# Модель истории пищи
class FoodHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    food_id = db.Column(db.Integer, db.ForeignKey('food.id'))
    food_date = db.Column(db.DateTime, default=datetime.utcnow)
    food_time = db.Column(db.Time)
    food_count = db.Column(db.Integer)

# Модель программы тренировок
class Program(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    program_name = db.Column(db.String(100))
    description = db.Column(db.Text)
    program_duration = db.Column(db.Integer)  # В днях
    # Связь с пользователями через тренеров
    user_trainers = db.relationship('UserTrainer', backref='program')
    trainer_id = db.Column(db.Integer, db.ForeignKey('trainer.id'))

# Модель связи пользователя и тренера
class UserTrainer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    program_id = db.Column(db.Integer, db.ForeignKey('program.id'))

# Модель плана питания
class MealPlan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    meal_plan_name = db.Column(db.String(100))
    description = db.Column(db.Text)
    trainer_id = db.Column(db.Integer, db.ForeignKey('trainer.id'))
    # Связь с историей питания
    meal_history = db.relationship('MealHistory', backref='meal_plan')

# Модель истории плана питания
class MealHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    meal_plan_id = db.Column(db.Integer, db.ForeignKey('meal_plan.id'))
    meal_date = db.Column(db.DateTime, default=datetime.utcnow)

class TrainingPlan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    plan_name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    exercises = db.Column(db.Text, nullable=False)  # Список упражнений

print(f"Database URI: {app.config['SQLALCHEMY_DATABASE_URI']}")

class TrainingExercise(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    training_id = db.Column(db.Integer, db.ForeignKey('training.id'))
    exercise_name = db.Column(db.String(100))
    description = db.Column(db.Text)
    # Дополнительные поля по необходимости

class ExerciseProgress(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    exercise_id = db.Column(db.Integer, db.ForeignKey('training_exercise.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    progress = db.Column(db.String(50))  # Статус выполнения (например, 'completed', 'not_completed')

# Декоратор для администратора
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('Эта страница доступна только для администраторов.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def send_via_ssh(local_file, remote_path, hostname, username, password, port=22):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(hostname, port, username, password)
        sftp = ssh.open_sftp()
        sftp.put(local_file, remote_path)
        sftp.close()
        ssh.close()
        return True
    except Exception as e:
        print(e)
        return False

def add_example_training_plans():
    # Убедимся, что не добавляем дубликаты
    if TrainingPlan.query.count() == 0:
        plans = [
            TrainingPlan(plan_name='Кардио Начальный', description='Кардио тренировка для начинающих', exercises='Бег на месте, Приседания'),
            TrainingPlan(plan_name='Сила Средний', description='Силовая тренировка для тех, кто уже имеет опыт', exercises='Отжимания, Подтягивания'),
            TrainingPlan(plan_name='Функциональная Средний', description='Функциональная тренировка средней сложности', exercises='Планка, Медицинский мяч'),
            TrainingPlan(plan_name='Кардио Продвинутый', description='Интенсивная кардио тренировка для продвинутых', exercises='Бег на трассе, Берпи'),
            TrainingPlan(plan_name='Сила Продвинутый', description='Сложная силовая тренировка для опытных', exercises='Тяга штанги, Приседания с гантелями'),
            TrainingPlan(plan_name='Йога Начальный', description='Йога для начинающих', exercises='Асаны для релаксации, Дыхательные упражнения'),
        ]
        db.session.bulk_save_objects(plans)
        db.session.commit()


#-------------------------------------------------------------------------------
def get_training_plan_by_id(plan_id):
    training_plan = TrainingPlan.query.filter_by(id=plan_id).first()
    print(f"get_training_plan_by_id: Полученный план для ID {plan_id}: {training_plan}")  # Добавлено логирование
    return training_plan

@app.route('/admin')
@login_required
@admin_required
def admin_panel():
    return render_template('admin_panel.html')

@app.route('/backup_db')
def backup_db():
    try:
        db_uri = current_app.config['SQLALCHEMY_DATABASE_URI']
        db_path = db_uri.replace('sqlite:///', '')
        if not os.path.exists(db_path):
            raise FileNotFoundError("Database file not found.")

        backup_dir = os.path.join(os.getcwd(), 'backups')
        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir)

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_file = f'backup_{timestamp}.db'
        backup_path = os.path.join(backup_dir, backup_file)

        shutil.copy2(db_path, backup_path)
        logging.info("Backup created successfully.")

        # Передача файла на удаленный сервер
        hostname = 'your-remote-host'
        username = 'your-username'
        password = 'your-password'
        remote_path = '/path/on/remote/server/' + backup_file

        if send_via_ssh(backup_path, remote_path, hostname, username, password):
            logging.info("Backup sent successfully.")
            return jsonify({"message": "Backup created and sent successfully", "backup_path": backup_path, "remote_path": remote_path})
        else:
            logging.error("Failed to send backup.")
            return jsonify({"error": "Backup created but sending failed"}), 500
    except Exception as e:
        logging.error(f"Backup failed: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/trainings/add', methods=['GET', 'POST'])
@login_required
def add_training_progress():
    training_plans = TrainingPlan.query.all()

    if request.method == 'POST':
        selected_plan_id = request.form.get('training_plan')
        progress_notes = request.form.get('progress_notes')

        # Здесь логика создания новой записи о прогрессе тренировки
        new_training_progress = TrainingHistory(
            user_id=current_user.id,
            training_plan_id=selected_plan_id,
            progress_notes=progress_notes,
            date=datetime.utcnow()
        )

        db.session.add(new_training_progress)
        db.session.commit()

        flash('Прогресс тренировки успешно добавлен.')
        return redirect(url_for('list_trainings'))

    return render_template('add_training_progress.html', training_plans=training_plans)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Неверное имя пользователя или пароль')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            flash('Пользователь с таким именем или email уже существует.')
            return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email=email, password=hashed_password, role='user')
        db.session.add(new_user)
        db.session.commit()

        flash('Вы успешно зарегистрировались! Теперь вы можете войти в систему.')
        return redirect(url_for('login'))

    return render_template('register.html')

def get_exercises_for_plan(plan_id):
    # Запрос к базе данных для получения упражнений, связанных с тренировочным планом
    exercises = TrainingExercise.query.filter_by(training_id=plan_id).all()
    return exercises
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы успешно вышли из системы.')
    return redirect(url_for('login'))

@app.route('/trainings')
def list_trainings():
    try:
        training_plans = TrainingPlan.query.all()
        if training_plans:
            print("Training Plans Found:", training_plans)
        else:
            print("No Training Plans Found. The database might be empty.")

        return render_template('trainings_list.html', training_plans=training_plans)
    except Exception as e:
        print(f"An error occurred while fetching training plans: {e}")
        # Можете также использовать `flash` для отображения ошибки в шаблоне, если это необходимо
        flash(f"An error occurred while fetching training plans: {e}")
        return redirect(url_for('index'))  # или любая другая страница для переадресации



@app.route('/trainers')
def list_trainers():
    try:
        trainers = Trainer.query.all()
        return render_template('trainers_list.html', trainers=trainers)
    except Exception as e:
        print(f"Ошибка при загрузке списка тренеров: {e}")
        flash(f'Произошла ошибка: {e}')
        return redirect(url_for('index'))


@app.route('/trainings/add', methods=['GET', 'POST'])
@login_required
def add_training():
    training_plans = TrainingPlan.query.all()

    if request.method == 'POST':
        selected_plan_id = request.form.get('training_plan')
        new_training = Training(
            # Здесь добавьте необходимые поля, например:
            training_name=selected_plan_id,
            # Остальные поля...
        )
        db.session.add(new_training)
        db.session.commit()
        flash('Новая тренировка успешно добавлена.')
        return redirect(url_for('list_trainings'))

    return render_template('add_training.html', training_plans=training_plans)

@app.route('/test_db')
def test_db():
    try:
        # Тестовый запрос к базе данных
        plans = TrainingPlan.query.all()
        return f"Number of plans: {len(plans)}"
    except Exception as e:
        # Возвращаем ошибку, если она возникла
        return f"An error occurred: {e}"

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

#---------------------------------------------------------------------------------------------
@app.route('/training_detail/<int:plan_id>')
def training_detail(plan_id):
    try:
        training_plan = get_training_plan_by_id(plan_id)
        if not training_plan:
            flash(f'Тренировочный план с ID {plan_id} не найден.')
            return redirect(url_for('index'))

        exercises = get_exercises_for_plan(plan_id)
        for exercise in exercises:
            progress = ExerciseProgress.query.filter_by(exercise_id=exercise.id, user_id=current_user.id).first()
            exercise.progress = progress.progress if progress else 'not_completed'

        return render_template('training_detail.html', training=training_plan, exercises=exercises)
    except Exception as e:
        flash(f'Произошла ошибка: {e}')
        return redirect(url_for('index'))



@app.route('/exercise/progress/<int:exercise_id>', methods=['POST'])
@login_required
def update_exercise_progress(exercise_id):
    try:
        progress_status = request.form.get('progress')
        progress_record = ExerciseProgress.query.filter_by(exercise_id=exercise_id, user_id=current_user.id).first()

        if not progress_record:
            progress_record = ExerciseProgress(exercise_id=exercise_id, user_id=current_user.id, progress=progress_status)
            db.session.add(progress_record)
        else:
            progress_record.progress = progress_status

        db.session.commit()
        flash('Прогресс упражнения обновлен.')
        return redirect(url_for('training_detail', plan_id=exercise_id))
    except Exception as e:
        flash(f'Произошла ошибка: {e}')
        return redirect(url_for('index'))


#-------------------------экспорт-----------------------------------
@app.route('/export_data', methods=['GET'])
@login_required
def export_data():
    try:
        format_type = request.args.get('format', 'csv')

        # Построение SQL-запроса с использованием SQLAlchemy
        query = User.query.statement
        sql_query = str(query.compile(db.session.bind))

        # Получение данных из базы данных
        data = pd.read_sql(sql_query, db.session.bind)

        if format_type == 'json':
            return jsonify(data.to_dict(orient="records"))
        elif format_type == 'csv':
            response = make_response(data.to_csv(index=False))
            response.headers["Content-Disposition"] = "attachment; filename=users_export.csv"
            response.headers["Content-Type"] = "text/csv"
            return response
        # Добавьте здесь код для обработки других форматов (PDF, XLSX)

    except Exception as e:
        logging.exception("An error occurred during exporting data")
        flash(f"An error occurred: {str(e)}")
        return redirect(url_for('index'))

@app.route('/')
def index():
    return render_template('index.html')



@app.route('/test_db_connection')
def test_db_connection():
    try:
        result = db.engine.execute('SELECT 1')
        return 'Database connection successful. Result: ' + str(result.fetchone())
    except Exception as e:
        return 'Database connection failed: ' + str(e)

@app.route('/meal_plans')
def list_meal_plans():
    meal_plans = MealPlan.query.all()
    return render_template('meal_plans_list.html', meal_plans=meal_plans)

@app.route('/meal_history')
@login_required
def meal_history():
    history = MealHistory.query.filter_by(user_id=current_user.id).all()
    return render_template('meal_history.html', history=history)

#---------------------------------admin-----------------------------------------
# Маршрут для страницы редактирования записи об истории тренировок
@app.route('/admin/edit_exercise/<int:exercise_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_exercise(exercise_id):
    exercise = TrainingExercise.query.get_or_404(exercise_id)
    if request.method == 'POST':
        exercise.exercise_name = request.form['exercise_name']
        exercise.description = request.form['description']
        db.session.commit()
        flash('Упражнение обновлено.')
        return redirect(url_for('training_detail', plan_id=exercise.training_id))
    return render_template('edit_exercise.html', exercise=exercise)

@app.route('/admin/delete_exercise/<int:exercise_id>', methods=['POST'])
@login_required
@admin_required
def delete_exercise(exercise_id):
    exercise = TrainingExercise.query.get_or_404(exercise_id)
    db.session.delete(exercise)
    db.session.commit()
    flash('Упражнение удалено.')
    return redirect(url_for('training_detail', plan_id=exercise.training_id))

@app.route('/admin/add_exercise/<int:training_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def add_exercise(training_id):
    if request.method == 'POST':
        new_exercise = TrainingExercise(
            training_id=training_id,
            exercise_name=request.form['exercise_name'],
            description=request.form['description']
        )
        db.session.add(new_exercise)
        db.session.commit()
        flash('Упражнение добавлено.')
        return redirect(url_for('training_detail', plan_id=training_id))
    return render_template('add_exercise.html', training_id=training_id)


#----------------------------------------------------------------
if __name__ == '__main__':
    # db.create_all() # Раскомментируйте эту строку, если не используете Flask-Migrate
    #add_example_training_plans()
    # with app.app_context():
   # add_example_training_plans()  # Вызовите эту функцию для заполнения базы данных
    app.run(debug=True)
   # from app import db, TrainingPlan

    #db.create_all()
   # plan1 = TrainingPlan(plan_name='Тестовый план', description='Описание', exercises='Упражнения')
    #db.session.add(plan1)
    #db.session.commit()