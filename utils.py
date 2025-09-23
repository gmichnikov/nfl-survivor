# utils.py
import json
from datetime import datetime, time, timedelta
import pytz
from app.models import WeeklyResult

# Season registration cutoff - no new registrations after this date
eastern = pytz.timezone('US/Eastern')
FIRST_WEEK_END = eastern.localize(datetime(2025, 9, 9, 5, 0))

def load_nfl_teams():
    with open('data/nfl_teams.json', 'r') as json_file:
        nfl_teams = json.load(json_file)
    return nfl_teams

def load_nfl_teams_as_pairs():
    teams = load_nfl_teams()
    return [(team['id'], team['name']) for team in teams]

def calculate_current_week():
    eastern = pytz.timezone('US/Eastern')

    first_week_deadline = eastern.localize(datetime(2025, 9, 7, 13, 0))
    now = datetime.now().astimezone(eastern)

    # datetime.now().astimezone(pytz.utc) maybe try this

    if now < first_week_deadline:
        return 1

    result = 2 + ((now - first_week_deadline).days // 7)
    return result

# this defines weeks as 5am Tues, where week 2 starts on the Tues after Week 1's MNF, used to see who needs to pick
def get_ongoing_week():
    now = datetime.now().astimezone(eastern)

    if now < FIRST_WEEK_END:
        return 1

    result = 2 + ((now - FIRST_WEEK_END).days // 7)
    return result

def calculate_game_week(game_time_utc):
    week_one_cutoff = datetime(2025, 9, 10, tzinfo=pytz.utc)
    
    if game_time_utc < week_one_cutoff:
        return 1
    
    delta_days = (game_time_utc - week_one_cutoff).days
    week_number = 2 + (delta_days // 7)
    
    return week_number

def is_pick_correct(user_pick, week):
    weekly_result = WeeklyResult.query.filter_by(week=week, team=user_pick).first()
    if weekly_result:
        return weekly_result.result == 'win' or weekly_result.result == 'tie'
    return False

def load_nfl_teams_as_dict():
    with open('data/nfl_teams.json', 'r') as json_file:
        nfl_teams = json.load(json_file)
    return {team['id']: team['name'] for team in nfl_teams}