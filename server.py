import os
import smtplib
import ssl
from datetime import datetime
from functools import wraps

from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_ckeditor import CKEditorField, CKEditor
from flask_ckeditor.utils import cleanify
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from sqlalchemy import ForeignKey
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, SubmitField, validators

from forms import LoginForm, RegistrationForm

load_dotenv()
app = Flask(__name__)
ckeditor = CKEditor(app)
app.secret_key = os.getenv('SECRET_KEY')

CURRENT_YEAR = datetime.now().year
MY_EMAIL_ADDRESS = os.getenv('EMAIL_ADDRESS')
PASSWORD = os.getenv('APP_PASSWORD')
smtp_server = "smtp.gmail.com"
context = ssl.create_default_context()


class BlogForm(FlaskForm):
    title = StringField('Blog Post Title', validators=[validators.DataRequired()])
    subtitle = StringField('Subtitle', )
    image_url = StringField('Blog Image URL', validators=[validators.DataRequired(), validators.url()])
    blog_content = CKEditorField(validators=[validators.DataRequired()])
    submit = SubmitField()


class CommentForm(FlaskForm):
    comment = CKEditorField(validators=[validators.DataRequired(), validators.Length(min=5, max=300)])
    submit = SubmitField('Post Comment')


class Base(DeclarativeBase):
    pass


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'

db = SQLAlchemy(model_class=Base, )
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, user_id)


class Post(db.Model):
    __tablename__ = 'posts'
    id: Mapped[int] = mapped_column(primary_key=True)
    author_id = mapped_column(ForeignKey('users.id'))
    author = relationship('User', back_populates='posts')
    title: Mapped[str] = mapped_column(nullable=False)
    body: Mapped[str] = mapped_column(nullable=False, unique=True)
    subtitle: Mapped[str] = mapped_column(nullable=True)
    image_url: Mapped[str] = mapped_column(nullable=False)
    date: Mapped[str] = mapped_column(db.DateTime, default=datetime.utcnow)
    comments = relationship('Comment', back_populates='post')


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(unique=True)
    password: Mapped[str] = mapped_column()
    name: Mapped[str] = mapped_column()
    # one-to-many relationship a user(post-writer) can have many posts
    posts = relationship('Post', back_populates='author')
    comments = relationship('Comment', back_populates='comment_author')


class Comment(db.Model):
    __tablename__ = 'comments'
    id: Mapped[int] = mapped_column(primary_key=True)
    comment_author_id = mapped_column(ForeignKey('users.id'))
    post_id = mapped_column(ForeignKey('posts.id'))
    text: Mapped[str] = mapped_column(nullable=False)
    date: Mapped[str] = mapped_column(db.DateTime, default=datetime.utcnow)
    comment_author = relationship('User', back_populates='comments')
    post = relationship('Post', back_populates='comments')


with app.app_context():
    db.create_all()


def check_if_admin(user: User) -> bool:
    return user.is_authenticated and user.id == 1


def admin_only(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not check_if_admin(current_user):
            abort(404)
        return func(*args, **kwargs)

    return decorated_function


@app.context_processor
def inject_globals():
    return {
        'copyright_year': CURRENT_YEAR,
        'user_is_logged_in': current_user.is_authenticated,
        'is_admin': check_if_admin(current_user)
    }


@app.route("/")
def home_page():
    return render_template('index.html', posts=Post.query.all(), )


@app.route("/about")
def about_page():
    return render_template('about.html')


@app.route("/contact")
def contact_page():
    return render_template('contact.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        password = form.password.data
        user = User.query.filter_by(email=form.email.data).scalar()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('home_page'))
        elif not user:
            flash('That email does not exist, please try again with a registered email')
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            flash('Incorrect Password')
            return redirect(url_for('login'))
    return render_template('login.html', form=form, )


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        old_user = User.query.filter_by(email=form.email.data).first()
        if old_user:
            flash('You are already registered. Log in Instead...')
            return redirect(url_for('login'))
        new_user = User(name=form.username.data,
                        email=form.email.data,
                        password=generate_password_hash(password=form.password.data))
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)

        return redirect(url_for('home_page'))
    return render_template('register.html', form=form)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('home_page'))


@app.route("/post/<int:index>", methods=['GET', 'POST'])
def show_full_post(index):
    requested_post = db.session.get(Post, index)
    form = CommentForm()
    if form.validate_on_submit():
        if current_user.is_authenticated:
            new_comment = Comment(text=form.comment.data, comment_author=current_user, post=requested_post)
            db.session.add(new_comment)
            db.session.commit()
            for comment in requested_post.comments:
                print(comment.text, comment.post_id, comment.comment_author_id)
            print("post author name" + current_user.name, f"post author id:{requested_post.author_id} title:"
                                                          f" {requested_post.title}")
        else:
            flash('Login or register to comment')
            return redirect(url_for('login'))
    return render_template('post.html', to_post=requested_post, form=form, )


@app.route('/delete-comment/<int:comment_id>', methods=['GET', 'POST'])
@login_required
def delete_comment(comment_id):
    comment_to_delete = db.session.get(Comment, comment_id)
    if comment_to_delete and comment_to_delete.comment_author_id == current_user.id:
        post_id = comment_to_delete.post_id
        db.session.delete(comment_to_delete)
        db.session.commit()

    return redirect(url_for('show_full_post', index=post_id))


@app.route("/form-entry", methods=['POST'])
def receive_data():
    try:
        server = smtplib.SMTP(smtp_server, 587)
        server.starttls(context=context)
        server.login(MY_EMAIL_ADDRESS, PASSWORD)
        server.sendmail(
            from_addr=MY_EMAIL_ADDRESS,
            to_addrs=MY_EMAIL_ADDRESS,
            msg=f"Subject: I Filled Your Blog Form\n\nMy name is {request.form['your_name']}\nMy Email address is {request.form['email_address']}\nMy phone Number is {request.form['phone_number']}\nMy message: {request.form['message']}"
        )
    except Exception as e:
        print("An error occurred", e)
    return redirect(url_for('home_page'))


@app.route('/new-post', methods=['GET', 'POST'])
@admin_only
def add_a_post():
    form = BlogForm()
    if form.validate_on_submit():
        new_post = Post(author=current_user,
                        title=form.title.data, subtitle=form.subtitle.data,
                        image_url=form.image_url.data, body=cleanify(form.blog_content.data))

        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for('home_page'))
    return render_template('make-post.html', form=form, heading='Add a post', editing=False, )


@app.route('/edit-post/<int:post_id>', methods=['GET', 'POST'])
@admin_only
def edit_post(post_id):
    post_to_edit = db.session.get(Post, post_id)
    form = BlogForm(
        blog_content=post_to_edit.body,
        title=post_to_edit.title,
        subtitle=post_to_edit.subtitle,
        image_url=post_to_edit.image_url,
    )
    if request.method == 'POST':
        if form.validate_on_submit():
            post_to_edit.body = cleanify(form.blog_content.data)
            post_to_edit.title = form.title.data
            post_to_edit.subtitle = form.subtitle.data
            post_to_edit.image_url = form.image_url.data
            post_to_edit.author = current_user
            db.session.commit()
            return redirect(url_for('home_page'))
    return render_template('make-post.html', form=form, heading='Edit Post', editing=True, )


@app.route('/delete/<int:post_id>', methods=['GET', 'POST'])
@admin_only
def delete_post(post_id):
    post_to_delete = db.session.get(Post, post_id)
    if post_to_delete:
        db.session.delete(post_to_delete)
        db.session.commit()
    return redirect(url_for('home_page'))


if __name__ == "__main__":
    app.run(debug=True)
