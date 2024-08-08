import base64
import hashlib
import hmac
import time
import uuid
import re 
import asyncio

import requests
import aiohttp
from bs4 import BeautifulSoup

default_headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    'accept-encoding':'gzip'
}

class TopScoreException(Exception):
  pass
          
class TopScoreClient(object):
  def __init__(self,  base_url, oauth_client_id = '' , oauth_client_secret = '' , email = '' , password = '' , headers = default_headers):
    
    if not base_url : raise TopScoreException(f"""base_url required""")
    
    self.base_url = base_url
    self.headers = headers
    
    #if these two not empty 
    if ( oauth_client_id and oauth_client_secret)  :
      
      self.oauth_client_id = oauth_client_id
      self.oauth_client_secret = oauth_client_secret
    
    #try logging in and scraping     
    elif  (email  and password ): 
      self.email = email 
      self.password = password
      
      #login with credentials and then scrape the oauth_client_id and oauth_client_secret 
      login_details = self.extract_oauth_tokens()
      self.oauth_client_id = login_details['Client ID [access_token]'] 
      self.oauth_client_secret = login_details['Client Secret']
      
    else:
      raise TopScoreException(f"""Either (oauth_client_id and oauth_client_secret) or (email and password) must be non empty
                              Received oauth_client_id:'{oauth_client_id}' oauth_client_secret:'{oauth_client_secret}' email:'{email}' password:'{password}'""")
      
    self.access_token = self.get_oauth_access_token()

  def get_oauth_access_token(self):
    url = f"{self.base_url}/api/oauth/server"
     
    oauth_params= {'grant_type':'client_credentials',
            'client_id':self.oauth_client_id,
            'client_secret':self.oauth_client_secret,
            }
    
    result = requests.post(url, data = oauth_params, headers = self.headers)

    if result.status_code == 200:
      access_token = result.json()['access_token']
      return(access_token)
    else:
      raise TopScoreException(f"OAuth Fail\n{result}")


  def extract_oauth_tokens(self):

    # Replace "ultimatecentral" with "usetopscore"
    self.base_url = re.sub(r"(?<=\.)ultimatecentral(?=\.com)", "usetopscore", self.base_url)
    
    # URL of the oauth-key page
    login_url = f'{self.base_url}/u/oauth-key'

    with requests.session() as s: 
      req = s.get(login_url, headers = default_headers).text 
      html = BeautifulSoup(req,"html.parser") 
      #get the token 
      token = html.find("input", {"name": "connect_id"}).attrs["value"] 

    # Construct the login request payload
    login_payload = {
    'signin[xvz32]': "" ,
    'signin[email]': self.email,
    'signin[account]': 'exists',
    'signin[password]': self.password,
    'signin[return_url]': login_url ,
    'signin[family_id]':  "" ,
    'connect_id': token
    }

    session = requests.Session()
    # Send login POST request, i.e. login
    login_post = session.post(login_url, data=login_payload, headers = default_headers)

    #login_post_html = BeautifulSoup(login_post.content.decode('utf-8'), 'html.parser')

    #Get oauth page
    response = session.get(login_url, headers = default_headers)

    logged_in_html = BeautifulSoup(response.content, 'html.parser')

    #Try to extract tokens
    try:
      table = logged_in_html.find('table', class_='table no-border')
      rows = table.find_all('tr')

      data = {}
      for row in rows:
        cells = row.find_all(['th', 'td'])
        if len(cells) > 1:
          key = cells[0].get_text(strip=True)
          value = cells[1].get_text(strip=True)
          data[key] =  value

      return(data)
    
    except Exception as e1:
    #attempt to catch known errors, i.e. wrong email/ password  
      try:
        login_error = login_post_html.find('div', class_='form-error')

        if login_error == "Please enter a valid email address." : raise TopScoreException(f"""{login_error}""")
        elif login_error == "Invalid password." : raise TopScoreException(f"""{login_error}""")
        else : raise TopScoreException(f"""{e1}""")

    #catch unknown errors
      except Exception as e2: 
        raise TopScoreException(f"""{e2}""")

  def csrf(self):
    #function currently unused
    nonce = bytes(str(uuid.uuid4()), 'ascii')
    ts = bytes(str(round(time.time())), 'ascii')
    message = bytes(self.client_id, 'ascii') + nonce + ts
    secret = bytes(self.client_secret, 'ascii')
    h = hmac.new(secret, message, digestmod=hashlib.sha256)
    return base64.urlsafe_b64encode(nonce + b'|' + ts + b'|' + base64.urlsafe_b64encode(h.digest()))

  def construct_url(self, endpoint):
    return f"{self.base_url}/api/{endpoint}"

  def get(self, endpoint, page=1, per_page=100, **params):
    params['page'] = page
    params['per_page'] = per_page
    access_token = self.access_token
    headers = {"Authorization": f"Bearer {self.access_token}"} | self.headers
    
    r = requests.get(self.construct_url(endpoint), params=params, headers=headers)
          
    return(r)

  def post(self, endpoint, data={}, page=1, per_page=100, **params):
    params['page'] = page
    params['per_page'] = per_page
    headers = {"Authorization": f"Bearer {self.access_token}"} | self.headers
    return requests.post(self.construct_url(endpoint), data=data, params=params, headers=headers)

  def get_me(self):
    r = self.post("me")
    return r.json()

  def update_game(self, game_id, field, value, **params):
    r = self.post("games/edit", data={
      'game_ids': [game_id],
      'field': field,
      'value': value
    }, **params)
    return r.json()

  #creator_id and end are required
  def update_event(self, event_id, creator_id, end,  **params):
    r = self.post("events/edit", data={
      'id': [event_id],
      creator_id : creator_id ,
      end : end ,
    }, **params)
    return r.json()

  def get_help(self):
    r = self.get("help")
    return r.json()

  def get_person(self, id, **params):
    r = self.get("persons", id=id, **params)
    return r.json()

  def get_tags_show(self, **params):
    r = self.get("tags/show", **params)
    return r.json()

  def get_games_show(self, **params):
    r = self.get("games/show", **params)
    return r.json()


  # async function to make a single request
  async def fetch(self, endpoint, session, page=1, per_page=100,  **params ):
    
    params['page'] = page
    params['per_page'] = per_page
    
    access_token = self.access_token
    headers = {"Authorization": f"Bearer {self.access_token}"} | self.headers
    
    #make request
    async with session.get(self.construct_url(endpoint), headers=headers, ssl=False,  params = params ) as response:
      rjson = await response.json()
      results = rjson['result'] 
      return results


  # async function to make multiple requests
  async def fetch_all(self, endpoint, page=1, per_page=100, **params):
    
    result = self.get(endpoint, page, per_page, **params).json()
    results = result['result']
    
    if result['status'] == 200:
      if 'count' in result:
        if result['count'] > (page * per_page):
          num_pages = int(result['count'] / per_page)

          async with aiohttp.ClientSession() as session:
            tasks = [self.fetch(endpoint, session , page = p + 1,  per_page = per_page , **params) for p in range(num_pages + 1 )]
            results = await asyncio.gather(*tasks)
            return results
        else:
          return [results]
    else:
      raise TopScoreException(f"Endpoint: {endpoint} \n Params: {params} \n Result:{result} \nUnable to get a paginated response from TopScore")
      
  def get_all_pages(self,endpoint, **params):
    endpoints = ["tags","games","registrations","events","persons","teams","fields","transactions","persons"]
    
    if endpoint in endpoints :
        return [item for sublist in asyncio.run(self.fetch_all(endpoint, **params)) for item in sublist]
    else: raise TopScoreException(f"{endpoint} not in {endpoints}")

  # non async functions to get data  
  def get_paginated(self, endpoint, page=1, per_page=100, **params):
    result = self.get(endpoint, page, per_page, **params).json()
    results = result['result']

    if result['status'] == 200:
      if 'count' in result:
        if result['count'] > (page * per_page):
          results += self.get_paginated(endpoint, page + 1, per_page, **params)
    else:
      raise TopScoreException(f"Endpoint: {endpoint} \n Params: {params} \n Result:{result} \nUnable to get a paginated response from TopScore")
    return results
    
  def get_tags(self, **params):
    return self.get_paginated("tags", **params)

  def get_games(self, **params):
    return self.get_paginated("games", **params)

  def get_registrations(self, **params):
    return self.get_paginated("registrations", **params)

  def get_events(self, **params):
    return self.get_paginated("events", **params)

  def get_people(self, **params):
    return self.get_paginated("persons", **params)

  def get_persons(self, id, **params):
    return self.get_paginated("persons", **params)

  def get_teams(self, **params):
    return self.get_paginated("teams", **params)

  def get_fields(self, **params):
    return self.get_paginated("fields", **params)

  def get_transactions(self, **params):
    return self.get_paginated("transactions", **params)

  def get_persons(self,  **params):
    return self.get_paginated("persons", **params)

