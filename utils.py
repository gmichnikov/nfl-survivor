# utils.py
import json
from datetime import datetime, time, timedelta
import pytz
from app.models import WeeklyResult

def load_nfl_teams():
    with open('data/nfl_teams.json', 'r') as json_file:
        nfl_teams = json.load(json_file)
    return nfl_teams

def load_nfl_teams_as_pairs():
    teams = load_nfl_teams()
    return [(team['id'], team['name']) for team in teams]

def calculate_current_week():
    # return 1
    eastern = pytz.timezone('US/Eastern')

    first_week_deadline = eastern.localize(datetime(2024, 9, 8, 13, 0))
    now = datetime.now().astimezone(eastern)
    # print("first week deadline: " + str(first_week_deadline))
    # print("now: " + str(now))

    # datetime.now().astimezone(pytz.utc) maybe try this
    # now = datetime(2024, 9, 2, 20, 0).astimezone(eastern) #fake

    if now < first_week_deadline:
        return 1

    result = 2 + ((now - first_week_deadline).days // 7)
    # print("Week is " + str(result))
    return result

def calculate_game_week(game_time_utc):
    # Define the cutoff date for week 1 in UTC timezone
    week_one_cutoff = datetime(2024, 9, 11, tzinfo=pytz.utc)
    
    # Check if the game is before the cutoff for week 1
    if game_time_utc < week_one_cutoff:
        return 1
    
    # Calculate the week number for games after week 1
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