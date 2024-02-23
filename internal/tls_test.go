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
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tetrateio/authservice-go/config/gen/go/v1/oidc"
)

const (
	smallCAPem = `-----BEGIN CERTIFICATE-----
MIIB8TCCAZugAwIBAgIJANZ3fvnlU+1IMA0GCSqGSIb3DQEBCwUAMF4xCzAJBgNV
BAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRAwDgYDVQQKDAdUZXRyYXRlMRQw
EgYDVQQLDAtFbmdpbmVlcmluZzESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI0MDIx
NjE1MzExOFoXDTI0MDIxNzE1MzExOFowXjELMAkGA1UEBhMCVVMxEzARBgNVBAgM
CkNhbGlmb3JuaWExEDAOBgNVBAoMB1RldHJhdGUxFDASBgNVBAsMC0VuZ2luZWVy
aW5nMRIwEAYDVQQDDAlsb2NhbGhvc3QwXDANBgkqhkiG9w0BAQEFAANLADBIAkEA
17tRxNJNLZVu2ntW/ehw5BneJFV+o7UmpCipv0zBtMtgJw2Z04fYiipaXgwg/sVL
wnyFgbhd0OgoIEg+ND38iQIDAQABozwwOjASBgNVHRMBAf8ECDAGAQH/AgEBMA4G
A1UdDwEB/wQEAwIC5DAUBgNVHREEDTALgglsb2NhbGhvc3QwDQYJKoZIhvcNAQEL
BQADQQAnQuyYJ6FbTuwtduT1ZCDcXMqTKcLb4ex3iaowflGubQuCX41yIprFScN4
2P5SpEcFlILZiK6vRzyPmuWEQVVr
-----END CERTIFICATE-----`

	invalidCAPem = `<invalid ca.pem>`
)

func TestLoadTLSConfig(t *testing.T) {
	tmpDir := t.TempDir()
	var (
		validFile   = tmpDir + "/valid.pem"
		invalidFile = tmpDir + "/invalid.pem"
	)
	require.NoError(t, os.WriteFile(validFile, []byte(smallCAPem), 0644))
	require.NoError(t, os.WriteFile(invalidFile, []byte(invalidCAPem), 0644))

	tests := []struct {
		name     string
		config   TLSConfig
		wantTLS  bool
		wantSkip bool
		wantPool bool
		wantErr  bool
	}{
		{
			name:    "no CA config",
			config:  &oidc.OIDCConfig{},
			wantTLS: false,
		},
		{
			name:     "skip verify config",
			config:   &oidc.OIDCConfig{TrustedCaConfig: &oidc.OIDCConfig_SkipVerifyPeerCert{SkipVerifyPeerCert: true}},
			wantTLS:  true,
			wantSkip: true,
		},
		{
			name:     "valid trusted CA string config",
			config:   &oidc.OIDCConfig{TrustedCaConfig: &oidc.OIDCConfig_TrustedCertificateAuthority{TrustedCertificateAuthority: smallCAPem}},
			wantTLS:  true,
			wantPool: true,
		},
		{
			name:    "invalid trusted CA string config",
			config:  &oidc.OIDCConfig{TrustedCaConfig: &oidc.OIDCConfig_TrustedCertificateAuthority{TrustedCertificateAuthority: invalidCAPem}},
			wantErr: true,
		},
		{
			name:     "valid trusted CA file config",
			config:   &oidc.OIDCConfig{TrustedCaConfig: &oidc.OIDCConfig_TrustedCertificateAuthorityFile{TrustedCertificateAuthorityFile: validFile}},
			wantTLS:  true,
			wantPool: true,
		},
		{
			name:    "invalid trusted CA file config",
			config:  &oidc.OIDCConfig{TrustedCaConfig: &oidc.OIDCConfig_TrustedCertificateAuthorityFile{TrustedCertificateAuthorityFile: invalidFile}},
			wantErr: true,
		},
		{
			name:    "no existing file trusted CA file config",
			config:  &oidc.OIDCConfig{TrustedCaConfig: &oidc.OIDCConfig_TrustedCertificateAuthorityFile{TrustedCertificateAuthorityFile: "non-existing.pem"}},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := LoadTLSConfig(tc.config)

			// Check for errors
			if tc.wantErr {
				require.Error(t, err)
				require.Nil(t, got)
				return
			}
			require.NoError(t, err)

			// Check for expected TLS config
			if !tc.wantTLS {
				require.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			require.Equal(t, tc.wantSkip, got.InsecureSkipVerify)
			require.Equal(t, tc.wantPool, got.RootCAs != nil)
		})
	}
}
