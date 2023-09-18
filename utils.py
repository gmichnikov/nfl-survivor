# utils.py
import json
from datetime import datetime, time, timedelta
import pytz
from app.models import WeeklyResult

def is_past_deadline(week):
    eastern = pytz.timezone('US/Eastern')
    first_week_deadline = datetime(2023, 9, 7, 20, 0).astimezone(eastern)  # Replace with the actual first week deadline date and time
    current_week_deadline = first_week_deadline + timedelta(days=(week - 1) * 7)
    now = datetime.now().astimezone(eastern)
    return now > current_week_deadline

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
    first_week_deadline = datetime(2023, 9, 7, 20, 0).astimezone(eastern)
    now = datetime.now().astimezone(eastern)
    # now = datetime(2024, 9, 2, 20, 0).astimezone(eastern) #fake

    if now < first_week_deadline:
        return 1

    result = 2 + ((now - first_week_deadline).days // 7)
    # print("Week calcd is " + str(result))
    return result

def is_pick_correct(user_pick, week):
    weekly_result = WeeklyResult.query.filter_by(week=week, team=user_pick).first()
    if weekly_result:
        return weekly_result.result == 'win' or weekly_result.result == 'tie'
    return False

def load_nfl_teams_as_dict():
    with open('data/nfl_teams.json', 'r') as json_file:
        nfl_teams = json.load(json_file)
    return {team['id']: team['name'] for team in nfl_teams}
