import os
from PIL import Image
from flask import Flask, render_template, request, url_for
from flask_login import LoginManager, login_user, login_required, logout_user, \
    current_user
from sqlalchemy import or_, and_
from werkzeug.exceptions import abort
from werkzeug.utils import redirect, secure_filename
from wtforms import PasswordField, SubmitField, TextAreaField, StringField, \
    BooleanField
from wtforms.fields.html5 import EmailField
from wtforms.validators import DataRequired
from data import db_session
from data.messages import Messages
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


class NewsForm(FlaskForm):
    title = StringField('Заголовок', validators=[DataRequired()])
    content = TextAreaField("Содержание")
    submit = SubmitField('Применить')


class AboutForm(FlaskForm):
    content = TextAreaField("Содержание")
    submit = SubmitField('Применить')


class UsersForm(FlaskForm):
    name = StringField('Имя', validators=[DataRequired()])
    submit = SubmitField('Применить')


class MessagesForm(FlaskForm):
    content = StringField("Сообщение", validators=[DataRequired()])
    submit = SubmitField('Отправить')


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
            'user': user,
            'news': news}
        return render_template('user.html', **param)

    if request.method == 'POST':
        user = session.query(User).filter(User.id == id).first()
        file = request.files['file']
        if file and allowed_file(file.filename):
            if user.photo != 'img/default.jpg':
                os.remove('static/img/' + str(user.id) + '(' + str(
                    user.photo_id) + ').' + user.photo.split('.')[-1])
            user.photo_id += 1
            filename = str(user.id) + '(' + str(user.photo_id) + ').' + \
                       file.filename.split('.')[-1]
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            user.photo = 'img/' + filename
            session.commit()
            resize('static/' + user.photo)
            return redirect('/user/{}'.format(user.id))
        else:
            pass


@app.route('/register', methods=['GET', 'POST'])
def register():
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


@app.route('/news', methods=['GET', 'POST'])
@login_required
def add_news():
    form = NewsForm()
    if form.validate_on_submit():
        session = db_session.create_session()
        news = News()
        news.title = form.title.data
        news.content = form.content.data
        current_user.news.append(news)
        session.merge(current_user)
        session.commit()
        return redirect('/user/{}'.format(current_user.id))
    return render_template('news.html', title='Добавление новости',
                           form=form)


@app.route('/news/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_news(id):
    form = NewsForm()
    if request.method == "GET":
        session = db_session.create_session()
        news = session.query(News).filter(News.id == id,
                                          News.user == current_user).first()
        if news:
            form.title.data = news.title
            form.content.data = news.content
        else:
            abort(404)
    if form.validate_on_submit():
        session = db_session.create_session()
        news = session.query(News).filter(News.id == id,
                                          News.user == current_user).first()
        if news:
            news.title = form.title.data
            news.content = form.content.data
            session.commit()
            return redirect('/user/{}'.format(current_user.id))
        else:
            abort(404)
    return render_template('news.html', title='Редактирование новости',
                           form=form)


@app.route('/news_delete/<int:id>', methods=['GET', 'POST'])
@login_required
def news_delete(id):
    session = db_session.create_session()
    news = session.query(News).filter(News.id == id,
                                      News.user == current_user).first()
    if news:
        session.delete(news)
        session.commit()
    else:
        abort(404)
    return redirect('/user/{}'.format(current_user.id))


@app.route('/user/<int:id>/about', methods=['GET', 'POST'])
@login_required
def edit_about(id):
    if current_user.id == id:
        form = AboutForm()
        if request.method == "GET":
            session = db_session.create_session()
            user = session.query(User).filter(User.id == id).first()
            if user:
                form.content.data = user.about
            else:
                abort(404)
        if form.validate_on_submit():
            session = db_session.create_session()
            user = session.query(User).filter(User.id == id).first()
            if user:
                user.about = form.content.data
                session.commit()
                return redirect('/user/{}'.format(current_user.id))
            else:
                abort(404)
        return render_template('about.html', title='Немного о себе',
                               form=form)
    else:
        return 'Эта страница принадлежит не вам!'


@app.route('/users', methods=['POST', 'GET'])
@login_required
def users():
    form = UsersForm()
    session = db_session.create_session()
    if form.validate_on_submit():
        users = session.query(User).filter(User.id != current_user.id,
                                           User.name.like(
                                               '%' + form.name.data + '%'))
        return render_template('users.html', users=users, form=form)
    users = session.query(User).filter(User.id != current_user.id)
    return render_template('users.html', users=users, form=form)


@app.route('/chat/<string:id>', methods=['POST', 'GET'])
@login_required
def chat(id):
    form = MessagesForm()
    session = db_session.create_session()
    user = session.query(User).filter(User.id == id.split('_')[1]).first()
    if form.validate_on_submit():
        message = Messages()
        message.content = form.content.data
        message.from_id = current_user.id
        message.to_id = id.split('_')[1]
        session.add(message)
        session.commit()
        messages = session.query(Messages).filter(
            or_(and_(Messages.from_id == current_user.id,
                     Messages.to_id == id.split('_')[1]),
                and_(Messages.from_id == id.split('_')[1],
                     Messages.to_id == current_user.id)))
        return render_template('messages.html', form=form, user=user,
                               messages=messages)
    messages = session.query(Messages).filter(
        or_(and_(Messages.from_id == current_user.id,
                 Messages.to_id == id.split('_')[1]),
            and_(Messages.from_id == id.split('_')[1],
                 Messages.to_id == current_user.id)))
    return render_template('messages.html', form=form, user=user,
                           messages=messages)


def main():
    db_session.global_init("db/network.sqlite")
    app.run()


if __name__ == '__main__':
    main()
