from urllib.parse import urlparse, unquote
from html.parser import HTMLParser
from keycloak import KeycloakAdmin
import requests
from urllib3.util import Retry
from requests.adapters import HTTPAdapter

CLIENT_ID = "authservice"
CLIENT_SECRET = "secret"
CALLBACK_URL = "https://localhost:9000/oauth/callback"

def setup_keycloak():
  # setup testuser
  admin = KeycloakAdmin(
    server_url="http://localhost:8443/auth/admin",
    username='admin',
    password='password',
    verify=False,
  )

  username = "test@example.com"
  user_id = admin.create_user({
    "username": username,
    "enabled": True
  })
  admin.set_user_password(
    user_id=user_id,
    password="password",
    temporary=False
  )

  # setup authservice client
  admin.create_client({
    "name": "authservice",
    "clientId": CLIENT_ID,
    "secret": CLIENT_SECRET,
    "redirectUris": [CALLBACK_URL]
  })


class SubmitFormExtractor(HTMLParser):
  def __init__(self) -> None:
      super().__init__()
      self.submit_form_url = ""

  def handle_starttag(self, tag, attrs):
    if tag == 'form': self._handle_form(attrs)

  def _handle_form(self, attrs):
    attrs_dict = self._to_dict(attrs)
    if attrs_dict['id'] == 'kc-form-login':
      self.submit_form_url = attrs_dict['action']

  def _to_dict(self, attrs):
    return {key: value for (key, value) in attrs}


def validate_unauthenticated_response(res):
  assert(res.status_code == 302)
  loc = res.headers['location']
  parsed_loc = urlparse(loc)

  queries = {}
  for raw_query in parsed_loc.query.split('&'):
    key, value = raw_query.split('=')
    queries[key] = value

  assert(queries['client_id'] == CLIENT_ID)
  assert(len(queries['nonce']) != 0)
  assert(unquote(queries['redirect_uri']) == CALLBACK_URL)
  assert(queries['response_type'] == "code")
  assert(queries['scope'] == "openid")
  assert(len(queries['state']) != 0)
  print("success validate_unauthenticated_response")


def validate_idp_authentication_response(res):
  assert(res.status_code == 302)
  assert(res.headers['Location'].startswith(CALLBACK_URL))
  print("success validate_idp_authentication_response")


def validate_token_fetch_callback_response(res):
  assert(res.status_code == 302)
  assert(res.headers['location'].startswith('https://localhost:9000/'))
  print("success validate_token_fetch_callback_response")


def check_idp_connectivity():
  session = requests.Session()
  session.mount("https://", HTTPAdapter(max_retries=Retry(total=10, connect=10, backoff_factor=1)))
  res = session.get(url='https://localhost:8443/auth/realms/master', verify=False)
  assert(res.status_code == 200)


def check_envoy_connectivity():
  session = requests.Session()
  session.mount("https://", HTTPAdapter(max_retries=Retry(total=10, connect=10, backoff_factor=1)))
  res = session.get(url='https://localhost:9000', verify=False)
  assert(res.status_code >= 100)


if __name__ == '__main__':
  check_idp_connectivity()
  check_envoy_connectivity()

  setup_keycloak()

  # 1, Check redicect after requested without valid cookie.
  res = requests.get(url='https://localhost:9000', verify=False, allow_redirects=False)
  sess_id = res.cookies.get('__Host-authservice-session-id-cookie')
  validate_unauthenticated_response(res)

  # 2, Check user authentication using valid userid/password, and expect to
  #    get redirect URL to authservice. 
  res = requests.get(url=res.headers['location'], verify=False, allow_redirects=False)
  extractor = SubmitFormExtractor()
  extractor.feed(res.content.decode('utf-8'))
  data = {
    'username': 'test@example.com',
    'password': 'password'
  }
  res = requests.post(url=extractor.submit_form_url, data=data, cookies=res.cookies,
    verify=False, allow_redirects=False)
  validate_idp_authentication_response(res)

  # 3. Request to callback endpoint which extracts IDToken/AToken from IDP.
  res = requests.get(url=res.headers['Location'], cookies={
    '__Host-authservice-session-id-cookie': sess_id
  }, verify=False, allow_redirects=False)
  validate_token_fetch_callback_response(res)

  # 4. Retry to request the page which requires authentication.
  res = requests.get(url=res.headers['Location'], cookies={
    '__Host-authservice-session-id-cookie': sess_id
  }, verify=False, allow_redirects=False)
  assert(res.status_code == 200)