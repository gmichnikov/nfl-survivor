from flask import render_template, redirect, url_for, flash, request
from app import app, db, login_manager
from app.models import User, Pick, WeeklyResult, Logs, Spread, ResetCode
from flask_login import login_user, logout_user, login_required, current_user
from app.forms import RegistrationForm, LoginForm, TeamSelectionForm, AdminPasswordResetForm, AdminSetPickForm, AdminGenerateResetCodeForm, UserResetPasswordForm
from utils import load_nfl_teams, load_nfl_teams_as_pairs, calculate_current_week, is_pick_correct, load_nfl_teams_as_dict, calculate_game_week, get_ongoing_week
from datetime import datetime, timedelta
import pytz
from pytz import timezone
import requests
import os
import json
from collections import OrderedDict
import secrets


@app.route('/')
def index():
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
        
        # Check if username matches admin username from environment variable
        from config import ADMIN_USERNAME
        if ADMIN_USERNAME and form.username.data == ADMIN_USERNAME:
            new_user.is_admin = True

        db.session.add(new_user)
        db.session.commit()

        # Log the registration action
        eastern = pytz.timezone('US/Eastern')
        log_time = datetime.now().astimezone(pytz.utc)

        action_type = "register"
        description = f"{new_user.username} registered"
        
        # Add special logging for admin user creation
        if new_user.is_admin:
            action_type = "admin_register"
            description = f"{new_user.username} registered as admin user"

        new_log = Logs(timestamp=log_time,
                      user_id=new_user.id,
                      action_type=action_type,
                      description=description)
        
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
        log_time = datetime.now().astimezone(pytz.utc)
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

    if current_week > 18:
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
    # picked_teams_for_list = {pick.week: pick.team for pick in previous_picks}
    picked_teams_for_list = {pick.week: (pick.team, pick.is_correct) for pick in previous_picks}

    sorted_weeks = sorted(picked_teams_for_list.keys())
    # picked_team_names = OrderedDict((week, team_lookup.get(picked_teams_for_list[week], picked_teams_for_list[week])) for week in sorted_weeks)
    picked_team_names = OrderedDict(
        (week, (team_lookup.get(picked_teams_for_list[week][0], picked_teams_for_list[week][0]), picked_teams_for_list[week][1])) 
        for week in sorted_weeks
    )

    selected_week = int(request.form.get('week_selector', current_week))

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
        log_time = datetime.now().astimezone(pytz.utc)
        team_name = dict(available_teams).get(form.team_choice.data)
        
        new_log = Logs(timestamp=log_time,
                      user_id=current_user.id,
                      action_type="pick",
                      description=f"{current_user.username} picked {team_name} for Week {form.week.data}")
        
        db.session.add(new_log)
        db.session.commit()
        flash('Your pick has been submitted.')
        return redirect(url_for('pick'))

    eastern = pytz.timezone('US/Eastern')
    utc = timezone('UTC')

    current_time_utc = datetime.now(pytz.utc)
    time_24_hours_ago = current_time_utc - timedelta(hours=24)

    spreads = Spread.query.filter(Spread.game_time > time_24_hours_ago).order_by(Spread.game_time).all()
    spreads_by_week = {}

    for spread in spreads:
        spread.game_time = utc.localize(spread.game_time).astimezone(eastern)
        if spread.week not in spreads_by_week:
            spreads_by_week[spread.week] = []
        spreads_by_week[spread.week].append(spread)

    last_updated_time = db.session.query(db.func.max(Spread.update_time)).filter_by(week=current_week).first()[0]
    if last_updated_time is None:
        max_week = db.session.query(db.func.max(Spread.week)).scalar()
        last_updated_time = db.session.query(db.func.max(Spread.update_time)).filter_by(week=max_week).first()[0]

    last_updated_time = utc.localize(last_updated_time).astimezone(eastern)
 
    return render_template('pick.html', form=form, future_weeks=future_weeks, all_picks=picked_team_names, selected_week=selected_week, spreads_by_week=spreads_by_week, last_updated_time=last_updated_time, current_week=current_week)

@app.route('/view_picks', methods=['GET'])
@login_required
def view_picks():
    all_picks = {}
    wrong_picks_count = {}
    correct_picks_count = {}
    users = User.query.all()

    team_lookup = {team['id']: team['name'] for team in load_nfl_teams()}

    for user in users:
        wrong_picks = Pick.query.filter_by(user_id=user.id, is_correct=False).count()
        correct_picks = Pick.query.filter_by(user_id=user.id, is_correct=True).count()
        wrong_picks_count[user.username] = wrong_picks
        correct_picks_count[user.username] = correct_picks

    sorted_users = sorted(users, key=lambda user: (
        wrong_picks_count.get(user.username, 0),          # Sort by wrong picks (ascending)
        -correct_picks_count.get(user.username, 0),       # Sort by correct picks (descending)
        user.username.lower()                             # Sort by username (case-insensitive)
    ))

    usernames = [user.username for user in sorted_users]

    for week in range(1, calculate_current_week()):
        all_picks[week] = {}
        picks_for_week = Pick.query.filter_by(week=week).all()

        for pick in picks_for_week:
            user = User.query.filter_by(id=pick.user_id).first()
            username = user.username
            team_name = team_lookup.get(pick.team, pick.team)
            all_picks[week][username] = {'team': team_name, 'is_correct': pick.is_correct}

    return render_template('view_picks.html', all_picks=all_picks, usernames=usernames, wrong_picks_count=wrong_picks_count)

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
            log_time = datetime.now().astimezone(pytz.utc)
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

    eastern = pytz.timezone('US/Eastern')
    utc = timezone('UTC')

    logs = Logs.query.order_by(Logs.timestamp.desc()).all()
    for log in logs:
        log.timestamp = utc.localize(log.timestamp).astimezone(eastern)
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
    form.username.choices = [(user.username, user.username) for user in sorted(User.query.all(), key=lambda user: user.username.lower())]
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

        team_lookup = load_nfl_teams_as_dict()
        team_name = team_lookup.get(form.team.data, "Unknown Team")

        # Log the action
        log_entry = Logs(
            timestamp=datetime.now().astimezone(pytz.utc),
            user_id=current_user.id,
            action_type="admin set pick",
            description=f"{current_user.username} set pick for {user.username} in week {form.week.data}: {team_name}"
        )
        db.session.add(log_entry)
        db.session.commit()

        flash('Pick set successfully.')
        return redirect(url_for('admin_set_pick'))

    return render_template('admin_set_pick.html', form=form)

@app.route('/fetch_spreads', methods=['GET'])
@login_required
def fetch_spreads():
    if not current_user.is_admin:
        flash('You do not have permission to access this page.')
        return redirect(url_for('index'))

    first_week_start_date = datetime(2025, 9, 4)
    current_week = calculate_current_week()
    days_shift = (current_week - 1) * 7
    commenceTimeFrom = datetime.now().astimezone(pytz.utc)
    current_week_sunday = first_week_start_date + timedelta(days=days_shift)
    commenceTimeTo = current_week_sunday + timedelta(days=7)

    commenceTimeFrom_str = commenceTimeFrom.strftime('%Y-%m-%dT%H:%M:%SZ')
    commenceTimeTo_str = commenceTimeTo.strftime('%Y-%m-%dT%H:%M:%SZ')

    odds_response = requests.get(f'https://api.the-odds-api.com/v4/sports/americanfootball_nfl/odds', params={
        'api_key': os.environ.get('ODDS_API_KEY'),
        'bookmakers': 'draftkings,fanduel',
        'markets': 'spreads',
        'oddsFormat': 'american',
        'dateFormat': 'unix',
        'commenceTimeFrom': commenceTimeFrom_str,
        'commenceTimeTo': commenceTimeTo_str
    })


    if odds_response.status_code != 200:
        flash(f'Failed to get odds: status_code {odds_response.status_code}, response body {odds_response.text}')
        return redirect(url_for('index'))

    odds_json = odds_response.json()
    for game in odds_json:
        odds_id = game['id']
        game_time_epoch = game['commence_time']
        home_team = game['home_team']
        away_team = game['away_team']
        
        game_time_utc = datetime.fromtimestamp(game_time_epoch, pytz.utc)

        draftkings_data = None
        fanduel_data = None
        
        for bookmaker in game['bookmakers']:
            if bookmaker['key'] == 'draftkings':
                draftkings_data = bookmaker
            elif bookmaker['key'] == 'fanduel':
                fanduel_data = bookmaker

        spread_data = draftkings_data if draftkings_data else fanduel_data

        if not spread_data:
            continue  # Skip this game if neither exists

        existing_entry = Spread.query.filter_by(odds_id=odds_id).first()
        if existing_entry:
            # Update existing fields
            existing_entry.update_time = datetime.now().astimezone(pytz.utc)
            existing_entry.game_time = game_time_utc
            existing_entry.home_team = home_team
            existing_entry.road_team = away_team
            existing_entry.week = calculate_game_week(game_time_utc)
            for outcome in spread_data['markets'][0]['outcomes']:
                if outcome['name'] == home_team:
                    existing_entry.home_team_spread = outcome['point']
                elif outcome['name'] == away_team:
                    existing_entry.road_team_spread = outcome['point']
        else:
            # Create new Spreads object and populate fields
            new_spread = Spread(
                odds_id=odds_id,
                update_time=datetime.now().astimezone(pytz.utc),
                game_time=game_time_utc,
                home_team=home_team,
                road_team=away_team,
                week=calculate_game_week(game_time_utc)
            )

            # Populate home_team_spread and road_team_spread
            for outcome in spread_data['markets'][0]['outcomes']:
                if outcome['name'] == home_team:
                    new_spread.home_team_spread = outcome['point']
                elif outcome['name'] == away_team:
                    new_spread.road_team_spread = outcome['point']

            # Add new record to the session
            db.session.add(new_spread)

        db.session.commit()

    current_week = calculate_current_week()

    eastern = pytz.timezone('US/Eastern')
    log_entry = Logs(
        timestamp=datetime.now().astimezone(pytz.utc),
        user_id=current_user.id,
        action_type="fetch_spreads",
        description=f"{current_user.username} fetched spreads for week {current_week}"
    )
    db.session.add(log_entry)
    db.session.commit()

    remaining_requests = odds_response.headers['x-requests-remaining']
    used_requests = odds_response.headers['x-requests-used']

    utc = timezone('UTC')

    current_time_utc = datetime.now(pytz.utc)
    time_24_hours_ago = current_time_utc - timedelta(hours=24)

    spreads = Spread.query.filter(Spread.game_time > time_24_hours_ago).order_by(Spread.game_time).all()
    # spreads = Spread.query.filter_by(week=current_week).order_by(Spread.game_time).all()
    for spread in spreads:
        spread.game_time = utc.localize(spread.game_time).astimezone(eastern)

    last_updated_time = db.session.query(db.func.max(Spread.update_time)).filter_by(week=current_week).first()[0]
    if last_updated_time is None:
        max_week = db.session.query(db.func.max(Spread.week)).scalar()
        last_updated_time = db.session.query(db.func.max(Spread.update_time)).filter_by(week=max_week).first()[0]

    last_updated_time = utc.localize(last_updated_time).astimezone(eastern)

    return render_template('fetch_spreads.html', 
                           spreads=spreads, 
                           last_updated_time=last_updated_time, 
                           current_week=current_week, 
                           remaining_requests=remaining_requests, 
                           used_requests=used_requests)

@app.route('/auto-update', methods=['GET', 'POST'])
@login_required
def auto_update():
    if not current_user.is_admin:
        flash('You do not have permission to access this page.')
        return redirect(url_for('index'))

    if request.method == 'POST':
        week_number = request.form.get('week_number')
        if week_number:
            try:
                week_number = int(week_number)
                results = fetch_results_for_week(week_number)
                # Process and update the database
                update_weekly_results(week_number, results)
                flash('Weekly results updated for week ' + str(week_number))
            except ValueError:
                flash('Invalid week number')
            except Exception as e:
                flash('Error updating results: ' + str(e))

        return redirect(url_for('auto_update'))

    return render_template('auto_update.html')

def update_weekly_results(week, results):
    team_name_to_id = map_team_names_to_ids()

    for team_name, result in results.items():
        team_id = team_name_to_id.get(team_name)

        if team_id:
            # Check if there's an existing record for this team and week
            weekly_result = WeeklyResult.query.filter_by(week=week, team=team_id).first()

            if weekly_result:
                # Update existing record
                weekly_result.result = result
            else:
                # Create a new record
                new_result = WeeklyResult(week=week, team=team_id, result=result)
                db.session.add(new_result)

    log_entry = Logs(
        timestamp=datetime.now().astimezone(pytz.utc),
        user_id=current_user.id,
        action_type="auto_update",
        description= current_user.username + " auto-updated results for week " + str(week)
    )
    db.session.add(log_entry)

    # Commit changes to the database
    db.session.commit()

    # Update Pick status
    all_picks = Pick.query.filter_by(week=week).all()
    print("picks for week: " + str(all_picks) + " for week " + str(week))
    for pick in all_picks:
        print("updating a pick: " + pick.team)
        pick.is_correct = is_pick_correct(pick.team, week)

    db.session.commit()

def fetch_results_for_week(week):
    url = f"https://site.api.espn.com/apis/site/v2/sports/football/nfl/scoreboard?dates=2025&seasontype=2&week={week}"
    response = requests.get(url)
    data = response.json()

    # Extract teams on bye
    # teams_on_bye = {team['displayName']: 'did not play' for team in data['week']['teamsOnBye']}
    teams_on_bye = {team['displayName']: 'did not play' for team in data['week'].get('teamsOnBye', [])}

    # Process game results
    game_results = {}
    for event in data['events']:
        for competition in event['competitions']:
            for competitor in competition['competitors']:
                team_name = competitor['team']['displayName']
                result = 'win' if competitor.get('winner', True) else 'lose'
                game_results[team_name] = result

    # Combine bye teams and game results
    all_results = {**teams_on_bye, **game_results}
    # print(json.dumps(all_results, indent=4))
    return all_results

def map_team_names_to_ids():
    teams = load_nfl_teams()
    return {team['name']: team['id'] for team in teams}

@app.route('/all_spreads')
@login_required
def all_spreads():
    if not current_user.is_admin:
        return redirect(url_for('index'))

    # Fetch all spreads from the database and order them by week
    eastern = pytz.timezone('US/Eastern')
    utc = timezone('UTC')
    spreads = Spread.query.order_by(Spread.week, Spread.game_time).all()
    for spread in spreads:
        spread.game_time = utc.localize(spread.game_time).astimezone(eastern)

    # Organize spreads by week
    spreads_by_week = {}
    for spread in spreads:
        if spread.week not in spreads_by_week:
            spreads_by_week[spread.week] = []
        spreads_by_week[spread.week].append(spread)

    return render_template('all_spreads.html', spreads_by_week=spreads_by_week)

@app.route('/admin_auto_pick', methods=['GET', 'POST'])
@login_required
def admin_auto_pick():
    if not current_user.is_admin:
        flash('You do not have permission to access this page.')
        return redirect(url_for('index'))

    if request.method == 'POST':
        week_number = int(request.form['week_number'])
        users = User.query.all()

        teams = load_nfl_teams()
        name_to_id_mapping = {team['name']: team['id'] for team in teams}

        for user in users:
            if not user_has_two_wrong_picks(user) and not user_made_pick_for_week(user, week_number):
                previously_picked_teams = get_previously_picked_teams(user, week_number)
                team_to_pick = find_team_with_most_negative_spread(previously_picked_teams, week_number)
                if team_to_pick:
                    team_id = name_to_id_mapping.get(team_to_pick)
                    print("Picking " + team_to_pick + " for " + user.username + " in week " + str(week_number))
                    pick = Pick(user_id=user.id, week=week_number, team=team_id, is_correct=None)
                    db.session.add(pick)

                    log_entry = Logs(
                        timestamp=datetime.now().astimezone(pytz.utc),
                        user_id=current_user.id,
                        action_type="auto_pick",
                        description= current_user.username + " auto-picking " + team_to_pick + " for " + user.username + " in week " + str(week_number)
                    )
                    db.session.add(log_entry)
        db.session.commit()
        flash('Auto picks set for week ' + str(week_number))
        return redirect(url_for('view_logs'))

    return render_template('admin_auto_pick.html')

def user_has_two_wrong_picks(user):
    wrong_picks_count = Pick.query.filter_by(user_id=user.id, is_correct=False).count()
    return wrong_picks_count >= 2

def user_made_pick_for_week(user, week):
    pick_exists = Pick.query.filter_by(user_id=user.id, week=week).first() is not None
    return pick_exists

# def get_previously_picked_teams(user, up_to_week):
#     picks = Pick.query.filter(Pick.user_id == user.id, Pick.week < up_to_week).all()
#     return [pick.team for pick in picks]

def get_previously_picked_teams(user, up_to_week):
    picks = Pick.query.filter(Pick.user_id == user.id, Pick.week < up_to_week).all()
    team_lookup = {team['id']: team['name'] for team in load_nfl_teams()}
    return [team_lookup.get(pick.team, pick.team) for pick in picks]

def find_team_with_most_negative_spread(previously_picked_teams, week_number):
    spreads = Spread.query.filter_by(week=week_number).all()
    most_negative_spread = None
    team_to_pick = None

    for spread in spreads:
        if spread.home_team not in previously_picked_teams and (most_negative_spread is None or spread.home_team_spread < most_negative_spread):
            most_negative_spread = spread.home_team_spread
            team_to_pick = spread.home_team

        if spread.road_team not in previously_picked_teams and (most_negative_spread is None or spread.road_team_spread < most_negative_spread):
            most_negative_spread = spread.road_team_spread
            team_to_pick = spread.road_team

    return team_to_pick

@app.route('/admin_view_weekly_results')
@login_required
def admin_view_weekly_results():
    if not current_user.is_admin:
        return "Access Denied", 403

    team_dict = load_nfl_teams_as_dict()

    weekly_results = WeeklyResult.query.all()

    results_by_team = {}
    for result in weekly_results:
        team_name = team_dict.get(result.team, 'Unknown Team')
        if team_name not in results_by_team:
            results_by_team[team_name] = {week: '' for week in range(1, 18)}
        results_by_team[team_name][result.week] = result.result
    sorted_results_by_team = dict(sorted(results_by_team.items()))

    return render_template('admin_view_weekly_results.html', results_by_team=sorted_results_by_team)

@app.route('/admin_view_all_picks')
@login_required
def admin_view_all_picks():
    if not current_user.is_admin:
        flash('You do not have permission to access this page.')
        return redirect(url_for('index'))

    users = User.query.all()
    picks = Pick.query.all()
    team_lookup = load_nfl_teams_as_dict()

    picks_by_user = {user.username: {week: '' for week in range(1, 19)} for user in users}

    for pick in picks:
        user = User.query.get(pick.user_id)
        team_name = team_lookup.get(pick.team, pick.team)
        picks_by_user[user.username][pick.week] = team_name

    return render_template('admin_view_all_picks.html', picks_by_user=picks_by_user)

@app.route('/admin_view_users')
@login_required
def admin_view_users():
    if not current_user.is_admin:
        flash('You do not have permission to access this page.')
        return redirect(url_for('index'))

    ongoing_week = get_ongoing_week()
    users = User.query.all()
    user_data = []
    for user in users:
        picks = Pick.query.filter_by(user_id=user.id).all()
        wrong_picks = sum(1 for pick in picks if pick.is_correct is False)

        has_picked_for_this_week = any(pick.week == ongoing_week for pick in picks)
        needs_to_pick = "Yes" if (wrong_picks < 2) and not has_picked_for_this_week else ""

        user_data.append({
            'username': user.username,
            'id': user.id,
            'is_admin': user.is_admin,
            'picks_count': len(picks),
            'wrong_picks': wrong_picks,
            'needs_to_pick': needs_to_pick
        })

    return render_template('admin_view_users.html', users=user_data)

@app.route('/admin_generate_reset_code', methods=['GET', 'POST'])
@login_required
def admin_generate_reset_code():
    if not current_user.is_admin:
        flash('You do not have permission to access this page.')
        return redirect(url_for('index'))

    form = AdminGenerateResetCodeForm()
    form.username.choices = [(user.username, user.username) for user in User.query.all()]

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        code = secrets.token_urlsafe(16)
        reset_code = ResetCode(user_id=user.id, code=code)
        db.session.add(reset_code)

        log_entry = Logs(
            user_id=current_user.id,
            action_type="generate reset code",
            description=f"Generated reset code for user {user.username}"
        )
        db.session.add(log_entry)

        db.session.commit()

        flash(f'Reset code for {user.username}: {code}')

    return render_template('admin_generate_reset_code.html', form=form)

@app.route('/user_reset_password', methods=['GET', 'POST'])
def user_reset_password():
    form = UserResetPasswordForm()
    form.username.choices = [(user.username, user.username) for user in User.query.all()]

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        reset_code = ResetCode.query.filter_by(user_id=user.id, code=form.reset_code.data, used=False).order_by(ResetCode.created_at.desc()).first()

        if reset_code and reset_code.is_valid():
            user.set_password(form.new_password.data)
            reset_code.used = True

            log_entry = Logs(
                user_id=user.id,
                action_type="password reset",
                description=f"User {user.username} reset their password using a reset code"
            )
            db.session.add(log_entry)
            db.session.commit()

            flash('Your password has been reset successfully.')
            return redirect(url_for('login'))
        else:
            flash('Invalid or expired reset code.')

    return render_template('user_reset_password.html', form=form)

@app.route('/admin_delete_user/<int:user_id>', methods=['POST'])
@login_required
def admin_delete_user(user_id):
    if not current_user.is_admin:
        flash('You do not have permission to access this page.')
        return redirect(url_for('index'))

    user_to_delete = User.query.get_or_404(user_id)
    
    # Prevent admin from deleting themselves
    if user_to_delete.id == current_user.id:
        flash('You cannot delete your own account.')
        return redirect(url_for('admin_view_users'))
    
    # Store username for logging before deletion
    username_to_delete = user_to_delete.username
    
    try:
        # Delete all associated data in cascading manner
        # Delete all picks for this user
        Pick.query.filter_by(user_id=user_id).delete()
        
        # Delete all logs for this user
        Logs.query.filter_by(user_id=user_id).delete()
        
        # Delete all reset codes for this user
        ResetCode.query.filter_by(user_id=user_id).delete()
        
        # Finally delete the user
        db.session.delete(user_to_delete)
        
        # Log the deletion action
        log_entry = Logs(
            timestamp=datetime.now().astimezone(pytz.utc),
            user_id=current_user.id,
            action_type="delete user",
            description=f"{current_user.username} deleted user {username_to_delete} and all associated data"
        )
        db.session.add(log_entry)
        
        db.session.commit()
        flash(f'User {username_to_delete} and all associated data have been deleted successfully.')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting user: {str(e)}')
    
    return redirect(url_for('admin_view_users'))
