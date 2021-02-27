from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

from datetime import datetime
from flask_script import Manager
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, TextAreaField, BooleanField, PasswordField
from wtforms.validators import DataRequired, Email
from flask_humanize import Humanize

app = Flask(__name__)

manager = Manager(app)
app.debug = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'One of many worlds.'

# Login Config
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Database Config

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:pass@localhost/my_db'
db = SQLAlchemy(app)
humanize = Humanize(app)

@app.route('/')
def index():
    posts = Post.query.order_by(Post.created_on.desc()).all()
    return render_template('posts.html', posts=posts)

@app.route('/post/update/<int:id>/', methods=['GET', 'POST'])
def update(id):
    post = Post.query.get_or_404(id)
    if request.method == "POST":
        post.title = request.form['title']
        post.content = request.form['content']
        db.session.commit()
        flash('Your post has been updated.', category='success')
        return redirect(url_for('index'))
    else:
        return render_template('update.html', post=post)

@app.route('/post/delete/<int:id>/')
def delete(id):
    post = Post.query.get_or_404(id)
    db.session.delete(post)
    db.session.commit()
    flash('Your post has been deleted.', category="warning")
    return redirect(url_for('index'))

@app.route('/post/new/', methods=['GET', 'POST'])
def new_post():
    form = PostForm()
    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data
        group = db.session.query(Group).get(1).name
        user = current_user.username
        post = Post(title=title, content=content, created_by=user, group=group)
        db.session.add(post)
        db.session.commit()
        return redirect(url_for('index'))

    return render_template('new_post.html', form=form)

@app.route('/login/', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = db.session.query(User).filter(User.username == form.username.data).first()
        if user:
            if user.check_password(form.password.data):
                login_user(user)
                flash("Welcome to Piper Inc.")
                return redirect(url_for('index'))
            else:
                flash("Incorrect password.", category="warning")
        else:
            flash("This username is incorrect/nonexistent", category="warning")
    return render_template('loginpage.html', form=form)


@app.route('/signup/', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        flash("You're already logged in", "info")
        return redirect(url_for('index'))
    form = UserCreationForm()
    if form.validate_on_submit():
        user = db.session.query(User).filter(User.username == form.username.data).first()
        if user:
            flash("This username already exists. Pick another one.", category="warning")
        elif not form.password1.data == form.password1.data:
            flash("The passwords you have entered do not match.", category="warning")
        else:
            a = User(username=form.username.data, email=form.email.data)
            a.set_password(form.password1.data)
            db.session.add(a)
            db.session.commit()
            flash("Account creation was successful. You can now login.", category="success")
            return redirect(url_for('login'))

    return render_template('signuppage.html', form=form)

@app.route('/logout/')
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", category="info")
    return redirect(url_for('login'))

# Models
@login_manager.user_loader
def load_user(id):
    return db.session.query(User).get(id)

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer(), primary_key=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password_hash = db.Column(db.String(100), nullable=False)
    created_on = db.Column(db.DateTime(), default=datetime.utcnow)
    updated_on = db.Column(db.DateTime(), default=datetime.utcnow, onupdate=datetime.utcnow)

    post = db.relationship('Post', backref='post')
    comment = db.relationship('Comment', backref='comment')

    def __repr__(self):
        return "<{}:{}".format(self.id, self.username)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Group(db.Model):
    __tablename__ = 'group'
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(255), nullable=False, unique=True)
    created_on = db.Column(db.DateTime(), default=datetime.utcnow)

    posts = db.relationship('Post', backref='posts')

    def __repr__(self):
        return "<{}: Group>".format(self.name)



class Post(db.Model):
    __tablename__ = 'posts'
    id = db.Column(db.Integer(), primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text(), nullable=False)
    created_on = db.Column(db.DateTime(), default=datetime.utcnow)
    updated_on = db.Column(db.DateTime(), default=datetime.utcnow, onupdate=datetime.utcnow)

    created_by = db.Column(db.String(255), db.ForeignKey('users.username'))
    group = db.Column(db.String(150), db.ForeignKey('group.name'))

    comments = db.relationship('Comment', backref='comments')

    def __repr__(self):
        return "<{}:{}>".format(self.created_by, self.title[:10])



class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer(), primary_key=True)
    content = db.Column(db.String(255), nullable=False)
    created_on = db.Column(db.DateTime(), default=datetime.utcnow)
    created_by = db.Column(db.String(255), db.ForeignKey('users.username'))
    post = db.Column(db.String(255), db.ForeignKey('posts.title'))

    def __repr__(self):
        return "<{}:{}>".format(self.id, self.created_by)


# Forms

class UserCreationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired()])
    password1 = PasswordField('Password1', validators=[DataRequired()])
    password2 = PasswordField('Password2', validators=[DataRequired()])
    username = StringField(
                        validators=[DataRequired()],
                        render_kw={"class_": "form-control",
                                   "autofocus": "true",
                                   "placeholder": "Username"}
                        )
    email = StringField(
                        validators=[DataRequired()],
                        render_kw={"class_": "form-control",
                                   "autofocus": "true",
                                   "placeholder": "Email"}
                        )


    password1 = StringField(
                        validators=[DataRequired()],
                        render_kw={"class_": "form-control",
                                    "autofocus": "true",
                                    "placeholder": "Password"}
                        )
    password2 = StringField(
                        validators=[DataRequired()],
                        render_kw={"class_": "form-control",
                                    "autofocus": "true",
                                    "placeholder": "Re-enter Password"}
                        )


class PostForm(FlaskForm):
    title = StringField(
                        validators=[DataRequired()],
                        render_kw={"class_": "form-control",
                                   "autofocus": "true",
                                   'placeholder': "Type your title here...",
                                   'id': "title",
                                   'aria-label': "Title"}
                        )
    content = TextAreaField(
                        validators=[DataRequired()],
                        render_kw={"class_": "form-control",
                                   "autofocus": "true",
                                   "placeholder": "Type your post text here...",
                                   "id": "content",
                                   "aria-label": "content",
                                   "rows": "3"})


class CommentForm(FlaskForm):
    content = TextAreaField(
                        validators=[DataRequired()],
                        render_kw={"class_": "form-control",
                                   "autofocus": "true",
                                   "placeholder": "Type your post text here...",
                                   "id": "content",
                                   "aria-label": "content",
                                   "rows": "3"}
                            )


class LoginForm(FlaskForm):
    username = StringField(
                        validators=[DataRequired()],
                        render_kw ={"class_": "form-control",
                                    "autofocus": "true",
                                     "placeholder": "Username",
                                     }
                        )
    password = StringField(
                        validators=[DataRequired()],
                        render_kw ={"class_": "form-control",
                                    "autofocus": "true",
                                    "placeholder": "Password",
                                     }
                        )



if __name__=='__main__':
    manager.run()