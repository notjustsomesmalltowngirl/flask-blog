from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, validators, PasswordField


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[validators.DataRequired(), validators.Length(min=4, max=25)])
    email = StringField('Email Address',
                        validators=[validators.DataRequired(), validators.Email()])
    password = PasswordField('Password', validators=[validators.DataRequired(), validators.Length(min=5)])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[validators.EqualTo('password', message='Passwords must match')])
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[validators.DataRequired(), validators.Email()])
    password = PasswordField('Password', validators=[validators.DataRequired(), validators.Length(min=5)])
    submit = SubmitField('Log In')


