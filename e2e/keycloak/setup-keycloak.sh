#!/bin/bash

# Copyright 2024 Tetrate
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

KEYCLOAK_SERVER="http://keycloak:8080"
REALM="master"
USERNAME=authservice
PASSWORD=authservice
CLIENT_ID=authservice
CLIENT_SECRET=authservice-secret
REDIRECT_URL=https://host.docker.internal:8443/callback

set -ex

/opt/keycloak/bin/kcadm.sh update realms/${REALM} \
    -s accessTokenLifespan=10 \
    --realm "${REALM}" \
    --server "${KEYCLOAK_SERVER}" \
    --user "${KEYCLOAK_ADMIN}" \
    --password "${KEYCLOAK_ADMIN_PASSWORD}"

/opt/keycloak/bin/kcadm.sh create users \
    -s username="${USERNAME}" \
    -s enabled=true \
    --server "${KEYCLOAK_SERVER}" \
    --realm "${REALM}" \
    --user "${KEYCLOAK_ADMIN}" \
    --password "${KEYCLOAK_ADMIN_PASSWORD}"

/opt/keycloak/bin/kcadm.sh set-password \
    --username "${USERNAME}" \
    --new-password "${PASSWORD}" \
    --server "${KEYCLOAK_SERVER}" \
    --realm "${REALM}" \
    --user "${KEYCLOAK_ADMIN}" \
    --password "${KEYCLOAK_ADMIN_PASSWORD}"

/opt/keycloak/bin/kcreg.sh create \
    -s clientId="${CLIENT_ID}" \
    -s secret="${CLIENT_SECRET}" \
    -s "redirectUris=[\"${REDIRECT_URL}\"]" \
    -s consentRequired=false \
    --server "${KEYCLOAK_SERVER}" \
    --realm "${REALM}" \
    --user "${KEYCLOAK_ADMIN}" \
    --password "${KEYCLOAK_ADMIN_PASSWORD}"
