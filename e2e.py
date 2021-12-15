from keycloak import KeycloakAdmin
import requests

def setup_keycloak():
  # setup testuser
  admin = KeycloakAdmin(
    server_url="http://127.0.0.1:8080/auth/admin",
    username='admin',
    password='password',
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
    "clientId": "authservice",
    "secret": "secret",
    "redirectUris": [
      "https://localhost:9000/oauth/callback"
    ]
  })

if __name__ == '__main__':
  res = requests.get(url='https://localhost:9000', verify=False)
  print(res)
