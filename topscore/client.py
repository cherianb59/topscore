import base64
import hashlib
import hmac
import requests
import time
import uuid
import asyncio
import aiohttp

default_headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    'accept-encoding':'gzip'
}

class TopScoreException(Exception):
  pass


class TopScoreClient(object):
  def __init__(self, client_id, client_secret, base_url, oauth_client_id,oauth_client_secret, email, password, headers = default_headers):
    
    self.client_id = client_id
    self.client_secret = client_secret
    self.base_url = base_url
    
    self.oauth_client_id = oauth_client_id
    self.oauth_client_secret = oauth_client_secret
    self.email = email
    self.password = password
    self.headers = headers
    
    self.access_token = self.get_oauth_access_token()

  def get_oauth_access_token(self):
    url = f"{self.base_url}/api/oauth/server"
    oath_params= {'grant_type':'password',
            'client_id':self.oauth_client_id,
            'client_secret':self.oauth_client_secret,
            'username':self.email,
            'password':self.password,
            }
    result = requests.post(url, data = oath_params, headers = self.headers)
    
    if result.status_code == 200:
      access_token = result.json()['access_token']
      self.access_token = access_token
      return(access_token)
    else:
      raise TopScoreException(f"OAuth Fail\n{result}")
  
  def csrf(self):
    nonce = bytes(str(uuid.uuid4()), 'ascii')
    ts = bytes(str(round(time.time())), 'ascii')
    message = bytes(self.client_id, 'ascii') + nonce + ts
    secret = bytes(self.client_secret, 'ascii')
    h = hmac.new(secret, message, digestmod=hashlib.sha256)
    return base64.urlsafe_b64encode(nonce + b'|' + ts + b'|' + base64.urlsafe_b64encode(h.digest()))

  def construct_url(self, endpoint):
    return f"{self.base_url}/api/{endpoint}"

  def get(self, endpoint, page=1, per_page=100, **params):
    params['auth_token'] = self.client_id
    params['api_csrf'] = self.csrf().decode('ascii')
    params['page'] = page
    params['per_page'] = per_page
    access_token = self.access_token
    headers = {"Authorization": f"Bearer {self.access_token}"} | self.headers
    
    r = requests.get(self.construct_url(endpoint), params=params, headers=headers)
    rjson = r.json()
    
    if rjson['status'] == 401 and rjson['errors'][0]['message'] == "Invalid auth token." :      
      access_token = self.get_oauth_access_token()
      headers = {"Authorization": f"Bearer {self.access_token}"}
      r = requests.get(self.construct_url(endpoint), params=params, headers=headers)
      
    return(r)

  def post(self, endpoint, data={}, page=1, per_page=100, **params):
    params['auth_token'] = self.client_id
    params['api_csrf'] = self.csrf().decode('ascii')
    params['page'] = page
    params['per_page'] = per_page
    return requests.post(self.construct_url(endpoint), data=data, params=params)

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

  def get_help(self):
    r = self.get("help")
    return r.json()

  def get_me(self):
    r = self.post("me")
    return r.json()

  def get_person(self, id, **params):
    r = self.get("persons", id=id, **params)
    return r.json()

  def get_tags_show(self, **params):
    r = self.get("tags/show", **params)
    return r.json()

  def update_game(self, game_id, field, value, **params):
    r = self.post("games/edit", data={
      'game_ids': [game_id],
      'field': field,
      'value': value
    }, **params)
    return r.json()

  def get_games_show(self, **params):
    r = self.get("games/show", **params)
    return r.json()

  def get_all_pages(self,endpoint, **params):
    endpoints = ["tags","games","registrations","events","persons","teams","fields","transactions","persons"]
    
    if endpoint in endpoints :
        return [item for sublist in asyncio.run(self.fetch_all(endpoint, **params)) for item in sublist]
    else: raise TopScoreException(f"{endpoint} not in {endpoints}")
    
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

# async function to make a single request
  async def fetch(self, endpoint, session, page=1, per_page=100,  **params ):
    
    params['auth_token'] = self.client_id
    params['api_csrf'] = self.csrf().decode('ascii')
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
