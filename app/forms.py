from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired
from utils import load_nfl_teams, load_nfl_teams_as_pairs, calculate_current_week

import json

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# class TeamSelectionForm(FlaskForm):
#     team_choice = SelectField('Select an NFL Team', choices=load_nfl_teams())
#     submit = SubmitField('Submit')

class TeamSelectionForm(FlaskForm):
    current_week=calculate_current_week()
    week = SelectField('Select Week', choices=[(str(i), str(i)) for i in range(current_week, 18)])  # Adding the week selection here
    team_choice = SelectField('Select an NFL Team')
    submit = SubmitField('Submit')

class AdminPasswordResetForm(FlaskForm):
    username = SelectField('Select User', choices=[])  # Choices will be populated in the route
    new_password = PasswordField('New Password', validators=[DataRequired()])
    submit = SubmitField('Reset Password')

class AdminSetPickForm(FlaskForm):
    username = SelectField('Username', choices=[])  # Populate this dynamically
    week = SelectField('Week', choices=[(str(i), str(i)) for i in range(1, 18)])
    team = SelectField('Team', choices=[])  # Populate this dynamically
    submit = SubmitField('Set Pick')

class AdminGenerateResetCodeForm(FlaskForm):
    username = SelectField('Username', validators=[DataRequired()])
    submit = SubmitField('Generate Reset Code')

class UserResetPasswordForm(FlaskForm):
    username = SelectField('Username', validators=[DataRequired()])
    reset_code = StringField('Reset Code', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired()])
    submit = SubmitField('Reset Password')
