// Copyright 2024 Tetrate
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package internal

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

// TLSConfig is an interface for the TLS configuration of the AuthService.
type TLSConfig interface {
	// GetTrustedCertificateAuthority returns the trusted certificate authority PEM.
	GetTrustedCertificateAuthority() string
	// GetTrustedCertificateAuthorityFile returns the path to the trusted certificate authority file.
	GetTrustedCertificateAuthorityFile() string
	// GetSkipVerifyPeerCert returns whether to skip verification of the peer certificate.
	GetSkipVerifyPeerCert() bool
}

// LoadTLSConfig loads a TLS configuration from the given TLSConfig.
func LoadTLSConfig(config TLSConfig) (*tls.Config, error) {
	tlsConfig := &tls.Config{}

	// Load the trusted CA PEM from the config
	var ca []byte
	switch {

	case config.GetTrustedCertificateAuthority() != "":
		ca = []byte(config.GetTrustedCertificateAuthority())

	case config.GetTrustedCertificateAuthorityFile() != "":
		var err error
		ca, err = os.ReadFile(config.GetTrustedCertificateAuthorityFile())
		if err != nil {
			return nil, fmt.Errorf("error reading trusted CA file: %w", err)
		}

	case config.GetSkipVerifyPeerCert():
		tlsConfig.InsecureSkipVerify = true

	default:
		// No CA or skip verification, return nil TLS config
		return nil, nil
	}

	// Add the loaded CA to the TLS config
	if len(ca) != 0 {
		certPool, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("error creating system cert pool: %w", err)
		}

		if ok := certPool.AppendCertsFromPEM(ca); !ok {
			return nil, errors.New("could no load trusted certificate authority")
		}

		tlsConfig.RootCAs = certPool
	}

	return tlsConfig, nil
}
