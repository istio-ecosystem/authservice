jwk=$(curl https://www.googleapis.com/oauth2/v3/certs)
jwk=$(printf '%s' "${jwk}" | python -c 'import json,sys; print(json.dumps(sys.stdin.read()))')
echo "Finish fetching JWK, filled config map at authservice/templates/config.yaml, oidc.jwk field"
echo "${jwk}"

