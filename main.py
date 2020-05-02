import os
from PIL import Image
from flask import Flask, render_template, request, url_for
from flask_login import LoginManager, login_user, login_required, logout_user, \
    current_user
from werkzeug.exceptions import abort
from werkzeug.utils import redirect, secure_filename
from wtforms import PasswordField, SubmitField, TextAreaField, StringField, \
    BooleanField
from wtforms.fields.html5 import EmailField
from wtforms.validators import DataRequired
from data import db_session
from data.news import News
from flask_wtf import FlaskForm
from data.users import User

UPLOAD_FOLDER = 'static/img/'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

app = Flask(__name__)
login_manager = LoginManager()
login_manager.init_app(app)
app.config['SECRET_KEY'] = 'yandexlyceum_secret_key'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS


def resize(path):
    image = Image.open(path)
    w, h = image.size
    if w > h:
        resized_image = image.resize((250, 200))
    elif w < h:
        resized_image = image.resize((200, 250))
    else:
        resized_image = image.resize((200, 200))
    resized_image.save(path)


class RegisterForm(FlaskForm):
    name = StringField('Имя:', validators=[DataRequired()])
    surname = StringField('Фамилия:', validators=[DataRequired()])
    email = EmailField('Логин:', validators=[DataRequired()])
    password = PasswordField('Пароль:', validators=[DataRequired()])
    password_again = PasswordField('Повторите пароль:',
                                   validators=[DataRequired()])
    about = TextAreaField('Немного о себе')
    submit = SubmitField('Зарегистрироваться')


class LoginForm(FlaskForm):
    email = EmailField('Логин', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    remember_me = BooleanField('Запомнить меня')
    submit = SubmitField('Войти')


@login_manager.user_loader
def load_user(user_id):
    session = db_session.create_session()
    return session.query(User).get(user_id)


@app.route('/')
def start():
    if current_user.is_authenticated:
        return redirect('/user/{}'.format(current_user.id))
    else:
        return redirect('/login')


@app.route('/user/<int:id>', methods=['POST', 'GET'])
@login_required
def user(id):
    session = db_session.create_session()
    if request.method == 'GET':
        user = session.query(User).filter(User.id == id).first()
        news = session.query(News).filter((News.user == user))
        param = {
            'title': 'Профиль',
            'name': user.name,
            'surname': user.surname,
            'photo': url_for('static', filename=user.photo),
            'about': [user.about if user.about else 'Здесь пока ничего нет!'][
                0],
            'news': news}
        return render_template('index.html', **param)

    if request.method == 'POST':
        user = session.query(User).first()
        file = request.files['file']
        if file and allowed_file(file.filename):
            os.remove('static/img/' + str(user.id) + '(' + str(
                user.photo_id) + ').' + user.photo.split('.')[-1])
            user.photo_id += 1
            filename = str(user.id) + '(' + str(user.photo_id) + ').' + \
                       file.filename.split('.')[-1]
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            user.photo = 'img/' + filename
            session.commit()
            resize('static/' + user.photo)
            return redirect('/new')
        else:
            pass


@app.route('/register', methods=['GET', 'POST'])
def reqister():
    form = RegisterForm()
    session = db_session.create_session()
    if form.validate_on_submit():
        if form.password.data != form.password_again.data:
            return render_template('register.html', title='Регистрация',
                                   form=form,
                                   message="Пароли не совпадают")
        if session.query(User).filter(User.email == form.email.data).first():
            return render_template('register.html', title='Регистрация',
                                   form=form,
                                   message="Такой пользователь уже есть")
        user = User(
            name=form.name.data,
            surname=form.surname.data,
            email=form.email.data,
            about=form.about.data
        )
        user.set_password(form.password.data)
        session.add(user)
        session.commit()
        return redirect('/')
    return render_template('register.html', title='Регистрация', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        session = db_session.create_session()
        user = session.query(User).filter(
            User.email == form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            return redirect('/user/{}'.format(user.id))
        return render_template('login.html',
                               message="Неправильный логин или пароль",
                               form=form)
    return render_template('login.html', title='Авторизация', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect("/login")


def main():
    db_session.global_init("db/blogs.sqlite")
    app.run()


if __name__ == '__main__':
    main()
