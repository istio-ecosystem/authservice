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

CERTS_DIR := certs
SHELL     := bash

$(CERTS_DIR):
	@mkdir -p $(CERTS_DIR)

.PHONY: clean-certs
clean-certs:  ## Cleans the certificates
	@rm -rf $(CERTS_DIR)

ca/%: $(CERTS_DIR)  ## Generates the CA
	@echo "Generating $(*) CA"
	@openssl genrsa -out "$(CERTS_DIR)/ca.key" 4096
	@openssl req -x509 -new -sha256 -nodes -days 365 -key "$(CERTS_DIR)/ca.key" -out "$(CERTS_DIR)/ca.crt" \
		-subj "/C=US/ST=California/O=Tetrate/OU=Engineering/CN=$(*)" \
		-addext "basicConstraints=critical,CA:true,pathlen:1" \
		-addext "keyUsage=critical,digitalSignature,nonRepudiation,keyEncipherment,keyCertSign" \
		-addext "subjectAltName=DNS:$(*)"

certificate/%: $(CERTS_DIR)  ## Generates the certificates
	@echo "Generating $(*) cert"
	@openssl genrsa -out "$(CERTS_DIR)/$(*).key" 2048
	@openssl req -new -sha256 -key "$(CERTS_DIR)/$(*).key" -out "$(CERTS_DIR)/$(*).csr" \
		-subj "/C=US/ST=California/O=Tetrate/OU=Engineering/CN=$(*)" \
		-addext "subjectAltName=DNS:$(*)"
	@openssl x509 -req -sha256 -days 120 -in "$(CERTS_DIR)/$(*).csr" -out "$(CERTS_DIR)/$(*).crt" \
		-CA "$(CERTS_DIR)/ca.crt" -CAkey "$(CERTS_DIR)/ca.key" -CAcreateserial -CAserial $(CERTS_DIR)/ca.srl \
		-extfile <(printf "subjectAltName=DNS:$(*)")
