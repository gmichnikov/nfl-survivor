from flask import render_template, redirect, url_for, flash, request
from app import app, db
from app.models import User, Pick, WeeklyResult, Logs
from flask_login import login_user, logout_user, login_required, current_user, LoginManager
from app.forms import RegistrationForm, LoginForm, TeamSelectionForm, AdminPasswordResetForm, AdminSetPickForm
from utils import load_nfl_teams, load_nfl_teams_as_pairs, calculate_current_week, is_pick_correct, load_nfl_teams_as_dict
from datetime import datetime
import pytz


@app.route('/')
def index():
    # Check if a user is logged in
    if current_user.is_authenticated:
        username = current_user.username
        return render_template('index.html', logged_in=True, username=username)
    else:
        return render_template('index.html', logged_in=False)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            flash('Username already exists.')
            return redirect(url_for('register'))
        
        new_user = User(username=form.username.data)
        new_user.set_password(form.password.data)
        # Automatically make user 'greg' an admin
        if form.username.data.lower() == 'greg':
            new_user.is_admin = True

        db.session.add(new_user)
        db.session.commit()

        # Log the registration action
        eastern = pytz.timezone('US/Eastern')
        log_time = datetime.now().astimezone(eastern)

        new_log = Logs(timestamp=log_time,
                      user_id=new_user.id,
                      action_type="register",
                      description=f"{new_user.username} registered")
        
        db.session.add(new_log)

        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password')
    return render_template('login.html', form=form)

# Initialize the LoginManager
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# This sets the weekly results
@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if not current_user.is_admin:
        flash('You do not have permission to access this page.')
        return redirect(url_for('index'))

    teams = load_nfl_teams()
    # current_week = 1  # Replace with logic to determine the current week
    current_week = calculate_current_week() - 1

    if request.method == 'POST':
        for team in teams:
            team_id = team['id']
            result = request.form.get(f'result_{team_id}')
            
            weekly_result = WeeklyResult.query.filter_by(week=current_week, team=team_id).first()
            if weekly_result:
                weekly_result.result = result
            else:
                new_result = WeeklyResult(week=current_week, team=team_id, result=result)
                db.session.add(new_result)

        db.session.commit()

        all_picks = Pick.query.filter_by(week=current_week).all()
        for pick in all_picks:
            pick.is_correct = is_pick_correct(pick.team, current_week)
        db.session.commit()

        # Log the action of setting results
        eastern = pytz.timezone('US/Eastern')
        log_time = datetime.now().astimezone(eastern)
        new_log = Logs(timestamp=log_time,
                      user_id=current_user.id,
                      action_type="set results",
                      description=f"{current_user.username} set results for week {current_week}")

        db.session.add(new_log)
        db.session.commit()

        flash('Weekly results updated.')
        return redirect(url_for('view_picks'))

    # Fetch existing results for the current week
    existing_results = {result.team: result.result for result in WeeklyResult.query.filter_by(week=current_week)}

    return render_template('admin.html', teams=teams, week=current_week, existing_results=existing_results)

@app.route('/pick', methods=['GET', 'POST'])
@login_required
def pick():
    current_week = calculate_current_week()
    print("Current week is " + str(current_week))

    if current_week > 17:
        return redirect(url_for('view_picks'))

    wrong_picks = Pick.query.filter_by(user_id=current_user.id, is_correct=False).count()
    # print("wrong: "+ str(wrong_picks))
    if wrong_picks >= 2:
        flash('You have been eliminated.')
        return redirect(url_for('view_picks'))

    future_weeks = list(range(current_week, 18))

    previous_picks = Pick.query.filter_by(user_id=current_user.id).all()
    picked_teams = [pick.team for pick in previous_picks]

    team_lookup = load_nfl_teams_as_dict()
    picked_teams_for_list = {pick.week: pick.team for pick in previous_picks}
    picked_team_names = {week: team_lookup.get(team_id, team_id) for week, team_id in picked_teams_for_list.items()}
    selected_week = int(request.form.get('week_selector', current_week))

    print("Selected week is " + str(selected_week))

    available_teams = [(team_id, team_name) for (team_id, team_name) in load_nfl_teams_as_pairs() if team_id not in picked_teams]

    form = TeamSelectionForm()
    form.team_choice.choices = available_teams
    form.week.choices = [(str(w), str(w)) for w in range(current_week, 18)]  # Populate the choices for the week selection

    if form.validate_on_submit():
        existing_pick = Pick.query.filter_by(user_id=current_user.id, week=int(form.week.data)).first()
  
        if existing_pick:
            existing_pick.team = form.team_choice.data
        else:
            new_pick = Pick(user_id=current_user.id, week=int(form.week.data), team=form.team_choice.data)
            db.session.add(new_pick)

        # Log the pick action
        eastern = pytz.timezone('US/Eastern')
        log_time = datetime.now().astimezone(eastern)
        team_name = dict(available_teams).get(form.team_choice.data)
        
        new_log = Logs(timestamp=log_time,
                      user_id=current_user.id,
                      action_type="pick",
                      description=f"{current_user.username} picked {team_name}")
        
        db.session.add(new_log)

        db.session.commit()
        flash('Your pick has been submitted.')
        return redirect(url_for('pick'))

    return render_template('pick.html', form=form, future_weeks=future_weeks, all_picks=picked_team_names, selected_week=selected_week)

@app.route('/view_picks', methods=['GET'])
@login_required
def view_picks():
    all_picks = {}
    usernames = [user.username for user in User.query.all()]
    usernames.sort()  # Sort usernames alphabetically

    # Convert team IDs to names
    team_lookup = {team['id']: team['name'] for team in load_nfl_teams()}
    
    for week in range(3, calculate_current_week()):
        all_picks[week] = {}
        picks_for_week = Pick.query.filter_by(week=week).all()

        for pick in picks_for_week:
            username = User.query.filter_by(id=pick.user_id).first().username
            team_name = team_lookup.get(pick.team, pick.team)
            all_picks[week][username] = {'team': team_name, 'is_correct': pick.is_correct}

    return render_template('view_picks.html', all_picks=all_picks, usernames=usernames)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/admin_reset_password', methods=['GET', 'POST'])
@login_required
def admin_reset_password():
    if not current_user.is_admin:
        flash('You do not have permission to access this page.')
        return redirect(url_for('index'))

    form = AdminPasswordResetForm()
    form.username.choices = [(user.username, user.username) for user in User.query.all()]

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            user.set_password(form.new_password.data)
            db.session.commit()

            # Log the password reset action
            eastern = pytz.timezone('US/Eastern')
            log_time = datetime.now().astimezone(eastern)
            new_log = Logs(timestamp=log_time,
                          user_id=current_user.id,
                          action_type="password reset",
                          description=f"{current_user.username} reset the password for {user.username}")

            db.session.add(new_log)
            db.session.commit()

            flash('Password reset successfully.')
        else:
            flash('User not found.')

    return render_template('admin_reset_password.html', form=form)

@app.route('/view_logs')
@login_required
def view_logs():
    if not current_user.is_admin:
        flash('You do not have permission to access this page.')
        return redirect(url_for('index'))

    logs = Logs.query.all()  # Replace with your own query if needed
    return render_template('view_logs.html', logs=logs)

@app.route('/admin_view_picks', methods=['GET'])
@login_required
def admin_view_picks():
    if not current_user.is_admin:
        flash('You do not have permission to access this page.')
        return redirect(url_for('index'))

    current_week = calculate_current_week()
    team_lookup = load_nfl_teams_as_dict()
    
    picks = db.session.query(User, Pick).outerjoin(Pick, (User.id == Pick.user_id) & (Pick.week == current_week)).all()

    print("Team Lookup:", team_lookup)
    print("Picks:", picks)

    # Add this line in your route after loading team_lookup
    print("Sample Pick:", picks[0] if picks else "No picks")

    picks_with_names = [(user, team_lookup.get(pick.team, "Not Picked") if pick else "Not Picked") for user, pick in picks]
    print("Picks with names:", picks_with_names)

    return render_template('admin_view_picks.html', picks=picks_with_names, week=current_week)


@app.route('/admin_set_pick', methods=['GET', 'POST'])
@login_required
def admin_set_pick():
    if not current_user.is_admin:
        flash('You do not have permission to access this page.')
        return redirect(url_for('index'))

    form = AdminSetPickForm()
    form.username.choices = [(user.username, user.username) for user in User.query.all()]
    form.team.choices = load_nfl_teams_as_pairs()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        existing_pick = Pick.query.filter_by(user_id=user.id, week=int(form.week.data)).first()
        
        if existing_pick:
            existing_pick.team = form.team.data
        else:
            new_pick = Pick(user_id=user.id, week=int(form.week.data), team=form.team.data)
            db.session.add(new_pick)

        db.session.commit()

        # Log the action
        # log_entry = Logs(
        #     timestamp=datetime.now(pytz.timezone('US/Eastern')),
        #     user_id=current_user.id,
        #     action_type="admin set pick",
        #     description=f"{current_user.username} set pick for {user.username} in week {form.week.data}: {form.team.data}"
        # )
        # db.session.add(log_entry)
        # db.session.commit()

        # Inside if form.validate_on_submit():
        team_lookup = load_nfl_teams_as_dict()
        team_name = team_lookup.get(form.team.data, "Unknown Team")

        # Log the action
        log_entry = Logs(
            timestamp=datetime.now(pytz.timezone('US/Eastern')),
            user_id=current_user.id,
            action_type="admin set pick",
            description=f"{current_user.username} set pick for {user.username} in week {form.week.data}: {team_name}"
        )
        db.session.add(log_entry)
        db.session.commit()

        flash('Pick set successfully.')
        return redirect(url_for('admin_set_pick'))

    return render_template('admin_set_pick.html', form=form)
