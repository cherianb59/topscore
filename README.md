# TopScore API Client

[TopScore](http://www.usetopscore.com/) provides athletic league and event management for a variety of different sports -- Ultimate Frisbee, Rugby, Handball, and so on.   This is a client for their API.  API documentation can be found in [this Google Doc](https://docs.google.com/document/d/148SFmTpsdon5xoGpAeNCokrpaPKKOSDtrLNBHOIq5c4/edit#), and at https://usetopscore.com/api/help.

Not all functions of the API have been implmented, the focus has been getting data from the API. If there is a function you want submit an issue, or better yet a pull request

Installation
------------
This library isn't currently available on pypi yet, so you'll have to install by hand.  To do so:
  1. (optional but recommended) Activate the virtualenv for your use case
  2. At the base level of the library repository, run `python setup.py install`

Examples
--------
### Instantiate a client
```
>>> import topscore
>>> client = topscore.client.TopScoreClient(base_url='https://YOURSITE.usetopscore.com', oauth_client_id=TS_OAUTH_CLIENT_ID,oauth_client_secret=TS_OAUTH_CLIENT_SECRET, email=SITE_USERNAME_PASSWORD,  password=SITE_PASSWORD )
```
To get TS_OAUTH_CLIENT_ID and TS_OAUTH_CLIENT_SECRET , login to https://YOURSITE.usetopscore.com and go to  https://YOURSITE.usetopscore.com/u/oauth-key

Alternative just use your email and password

```
>>> import topscore
>>> client = topscore.client.TopScoreClient(base_url='https://YOURSITE.usetopscore.com', email=SITE_USERNAME_PASSWORD,  password=SITE_PASSWORD )
```

SITE_USERNAME_PASSWORD and SITE_PASSWORD are the email and password used to login for https://YOURSITE.usetopscore.com

### Get a list of games
```
>>> games = client.get_all_pages(endpoint='games', event_id=EVENT_ID)
>>> print(games[0])
{'AwayTeam': {'contact_email': '', 'created_at': '2017-04-22 18:05:07', 'slug': 'shredline-1', 'creator_id': 184880, 'color': None, 'media_item_id': None, 'attendance_window': 4320, 'school_id': None, 'location_id': 452856, 'sport_id': 1, 'images': {'20': 'https://d36m266ykvepgv.cloudfront.net/uploads/media/66h47QW8vx/s-20-20/uc-logomark-1.png', '200': 'https://d36m266ykvepgv.cloudfront.net/uploads/media/66h47QW8vx/s-200-200/uc-logomark-1.png', '280': 'https://d36m266ykvepgv.cloudfront.net/uploads/media/66h47QW8vx/s-280-280/uc-logomark-1.png', '370': 'https://d36m266ykvepgv.cloudfront.net/uploads/media/66h47QW8vx/s-370-370/uc-logomark-1.png', '40': 'https://d36m266ykvepgv.cloudfront.net/uploads/media/66h47QW8vx/s-40-40/uc-logomark-1.png'}, 'name': 'SHRedline', 'twitter_name': None, 'updated_at': '2017-04-28 20:37:43', 'date_breakup': None, 'type': None, 'is_event_team': False, 'organization_id': None, 'id': 198130, 'youtube_key': None, 'model': 'team', 'website': '', 'facebook_url': '', 'date_founded': None, 'site_id': 325}, 'start_datetime_tz': '0207-08-15 18:30:00', 'end_time': '20:30:00', 'division_name': 'All Teams', 'is_forfeit': False, 'created_at': '2017-07-11 14:49:45', 'away_game_report_score': None, 'end_date': '0207-08-15', 'stage_name': 'Regular Season', 'status': 'scheduled', 'home_game_report_score': None, 'stage_format': 'pool', 'field_reservation_id': None, 'stage_id': 116729, 'carryover_source_game_id': None, 'home_team_proxy_id': 497163, 'event_name': 'Summer Club League', 'home_team_id': 197972, 'home_team_description': 'Rubs the Duckie', 'field_id': None, 'updated_at': '2017-07-11 14:49:45', 'away_team_id': 198130, 'losing_team_id': None, 'is_locked': False, 'id': 632876, 'field_number': None, 'reported_at': None, 'away_team_description': 'SHRedline', 'end_datetime_tz': '0207-08-15 20:30:00', 'home_score': None, 'model': 'game', 'is_played': False, 'HomeTeam': {'contact_email': '', 'created_at': '2017-04-20 14:16:22', 'slug': 'rubs-the-duckie', 'creator_id': 155605, 'color': None, 'media_item_id': None, 'attendance_window': 4320, 'school_id': None, 'location_id': 469679, 'sport_id': 1, 'images': {'20': 'https://d36m266ykvepgv.cloudfront.net/uploads/media/66h47QW8vx/s-20-20/uc-logomark-1.png', '200': 'https://d36m266ykvepgv.cloudfront.net/uploads/media/66h47QW8vx/s-200-200/uc-logomark-1.png', '280': 'https://d36m266ykvepgv.cloudfront.net/uploads/media/66h47QW8vx/s-280-280/uc-logomark-1.png', '370': 'https://d36m266ykvepgv.cloudfront.net/uploads/media/66h47QW8vx/s-370-370/uc-logomark-1.png', '40': 'https://d36m266ykvepgv.cloudfront.net/uploads/media/66h47QW8vx/s-40-40/uc-logomark-1.png'}, 'name': 'Rubs the Duckie', 'twitter_name': None, 'updated_at': '2017-06-06 15:53:30', 'date_breakup': None, 'type': None, 'is_event_team': False, 'organization_id': None, 'id': 197972, 'youtube_key': None, 'model': 'team', 'website': '', 'facebook_url': '', 'date_founded': None, 'site_id': 325}, 'away_team_proxy_id': 497164, 'start_date': '0207-08-15', 'away_score': None, 'start_time': '18:30:00', 'winning_team_id': None}

```

### Update the start time of a game to 7:00PM
```
>>> client.update_game(GAME_ID, 'start_time', '19:00:00', event_id=EVENT_ID)
```

### Use the fields parameter to get more data 

```
>>> additional_fields = {"fields":"GameTeamProxys" , "fields[GameTeamProxys]" : "SurveyAnswerSets" }
>>> results = client.get_all_pages("games", id="1547633",**additional_fields)

{'model': 'game', 'id': 746992, 'stage_id': 122371, 'home_team_proxy_id': 617317, 'away_team_proxy_id': 617324, 'field_id': None, 'field_number': 5, 'winning_team_id': 165203, 'losing_team_id': 215899, 'start_date': '2018-04-26', 'end_date': '2018-04-26', 'start_time': '09:00:00', 'end_time': '09:00:00', 'start_datetime_tz': '2018-04-25 19:00:00', 'end_datetime_tz': '2018-04-25 19:00:00', 'home_score': 15, 'away_score': 13, 'home_game_report_score': 11, 'away_game_report_score': 10, 'is_played': True, 'is_forfeit': False, 'status': 'has_outcome', 'is_locked': True, 'is_practice': False, 'reported_at': '2018-04-26 13:32:06', 'carryover_source_game_id': None, 'field_reservation_id': None, 'created_at': '2018-04-19 13:26:15', 'updated_at': '2018-05-03 17:40:04', 'GameTeamProxys': [{'model': 'game_team_proxy', 'id': 1239758, 'game_id': 746992, 'team_proxy_id': 617317, 'is_attendance_sent': False, 'is_survey_sent': False, 'created_at': '2018-04-19 13:26:15', 'updated_at': '2018-04-19 13:26:15', 'SurveyAnswerSets': [{'model': 'survey_answer_set', 'id': 1203651, 'survey_id': 103440, 'score': 11, 'person_id': None, 'registration_id': None, 'event_id': None, 'game_team_proxy_id': 1239758, 'purchase_id': None, 'game_id': None, 'session_day_registration_id': None, 'created_at': '2018-04-26 00:44:04', 'updated_at': '2018-04-26 00:44:04'}], 'survey_answer_set_ids': [1203651]}, {'model': 'game_team_proxy', 'id': 1239759, 'game_id': 746992, 'team_proxy_id': 617324, 'is_attendance_sent': False, 'is_survey_sent': False, 'created_at': '2018-04-19 13:26:15', 'updated_at': '2018-04-19 13:26:15', 'SurveyAnswerSets': [{'model': 'survey_answer_set', 'id': 1203645, 'survey_id': 103440, 'score': 10, 'person_id': None, 'registration_id': None, 'event_id': None, 'game_team_proxy_id': 1239759, 'purchase_id': None, 'game_id': None, 'session_day_registration_id': None, 'created_at': '2018-04-26 00:40:25', 'updated_at': '2018-04-26 00:40:25'}], 'survey_answer_set_ids': [1203645]}], 'game_team_proxy_ids': [1239758, 1239759], 'stage_name': 'Initial Pool Play', 'division_name': "Men's", 'event_name': 'Australian Ultimate Championships 2018', 'stage_format': 'pool', 'home_team_id': 165203, 'away_team_id': 215899, 'home_team_description': 'Newcastle I-Beam', 'away_team_description': 'Power Lunch', 'HomeTeam': {'model': 'team', 'id': 165203, 'name': 'Newcastle I-Beam', 'slug': 'newcastle-i-beam-4', 'media_item_id': 170742, 'sport_id': 1, 'attendance_window': 4320, 'location_id': 82744, 'site_id': 856, 'organization_id': None, 'creator_id': None, 'is_event_team': False, 'color': '#752121', 'school_id': None, 'type': 'men', 'website': '', 'twitter_name': None, 'facebook_url': '', 'contact_email': None, 'date_founded': None, 'date_breakup': None, 'youtube_key': None, 'created_at': '2015-11-09 19:29:11', 'updated_at': '2024-01-05 08:56:04', 'images': {'20': 'https://d36m266ykvepgv.cloudfront.net/uploads/media/3ytKb9Wgba/s-20-20/ibeam1-1.gif', '40': 'https://d36m266ykvepgv.cloudfront.net/uploads/media/3ytKb9Wgba/s-40-40/ibeam1-1.gif', '200': 'https://d36m266ykvepgv.cloudfront.net/uploads/media/3ytKb9Wgba/s-200-200/ibeam1-1.gif', '280': 'https://d36m266ykvepgv.cloudfront.net/uploads/media/3ytKb9Wgba/s-280-280/ibeam1-1.gif', '370': 'https://d36m266ykvepgv.cloudfront.net/uploads/media/3ytKb9Wgba/s-370-370/ibeam1-1.gif'}}, 'AwayTeam': {'model': 'team', 'id': 215899, 'name': 'Power Lunch', 'slug': 'power-lunch-1', 'media_item_id': 240452, 'sport_id': 1, 'attendance_window': 4320, 'location_id': 556224, 'site_id': 856, 'organization_id': None, 'creator_id': 139966, 'is_event_team': False, 'color': '#000000', 'school_id': None, 'type': 'men', 'website': '', 'twitter_name': None, 'facebook_url': '', 'contact_email': '', 'date_founded': None, 'date_breakup': None, 'youtube_key': None, 'created_at': '2018-01-11 23:50:58', 'updated_at': '2018-03-06 05:34:10', 'images': {'20': 'https://d36m266ykvepgv.cloudfront.net/uploads/media/K5dUqv5gIS/s-20-20/lunch-dark-1.png', '40': 'https://d36m266ykvepgv.cloudfront.net/uploads/media/K5dUqv5gIS/s-40-40/lunch-dark-1.png', '200': 'https://d36m266ykvepgv.cloudfront.net/uploads/media/K5dUqv5gIS/s-200-200/lunch-dark-1.png', '280': 'https://d36m266ykvepgv.cloudfront.net/uploads/media/K5dUqv5gIS/s-280-280/lunch-dark-1.png', '370': 'https://d36m266ykvepgv.cloudfront.net/uploads/media/K5dUqv5gIS/s-370-370/lunch-dark-1.png'}}, 'field_name': 'TBD'}

```

### Use the fields parameter to get spirit scores for all games in an event

```
>>> survey_field_params = {"fields[Stage]":"Stage", "fields[GameTeamProxys]":"GameTeamProxys" , "fields[GameTeamProxys]" : "SurveyAnswerSets", "fields[GameTeamProxys][SurveyAnswerSets]" : "SurveyAnswers" }
>>> games = client.get_all_pages("games", event_id = XXXXXXXXX ,**survey_field_params)
