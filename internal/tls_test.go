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
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/tetrateio/authservice-go/config/gen/go/v1/oidc"
)

const (
	invalidCAPem      = `<invalid ca.pem>`
	firstCertDNSName  = "testing"
	secondCertDNSName = "other"

	firstCAPem = `-----BEGIN CERTIFICATE-----
MIICNjCCAeCgAwIBAgIUCUxfyLHNslm/jteqHDJdiYxVo+gwDQYJKoZIhvcNAQEL
BQAwXDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExEDAOBgNVBAoM
B1RldHJhdGUxFDASBgNVBAsMC0VuZ2luZWVyaW5nMRAwDgYDVQQDDAd0ZXN0aW5n
MB4XDTI0MDIyMzEyMTYzMFoXDTI0MDIyNDEyMTYzMFowXDELMAkGA1UEBhMCVVMx
EzARBgNVBAgMCkNhbGlmb3JuaWExEDAOBgNVBAoMB1RldHJhdGUxFDASBgNVBAsM
C0VuZ2luZWVyaW5nMRAwDgYDVQQDDAd0ZXN0aW5nMFwwDQYJKoZIhvcNAQEBBQAD
SwAwSAJBAL5+wV2XPh0l6cwUS4CWqddSfKww6XD0YdKXjjKQZMNo6pZfRfmPIalk
ExNZF8rbCmpk3XJqmh9mpKKPFCNJEbECAwEAAaN6MHgwHQYDVR0OBBYEFD2aRQZN
sH7eVIv2CN+PiTYz2LV4MB8GA1UdIwQYMBaAFD2aRQZNsH7eVIv2CN+PiTYz2LV4
MBIGA1UdEwEB/wQIMAYBAf8CAQEwDgYDVR0PAQH/BAQDAgLkMBIGA1UdEQQLMAmC
B3Rlc3RpbmcwDQYJKoZIhvcNAQELBQADQQCK9MOCDozutKvtEQ8piLVlkR5EmtWn
33SDPZXeCD4wLyULP8OFayar0rBLaGB33OeKOffQ8xiNF7MD4pOicFlU
-----END CERTIFICATE-----`

	firstCertPem = `-----BEGIN CERTIFICATE-----
MIICEjCCAbygAwIBAgIUZ92xILVsEMxFXr4DJLFpZXp1O5MwDQYJKoZIhvcNAQEL
BQAwXDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExEDAOBgNVBAoM
B1RldHJhdGUxFDASBgNVBAsMC0VuZ2luZWVyaW5nMRAwDgYDVQQDDAd0ZXN0aW5n
MB4XDTI0MDIyMzEyMTYzMFoXDTI0MDIyNDEyMTYzMFowXDELMAkGA1UEBhMCVVMx
EzARBgNVBAgMCkNhbGlmb3JuaWExEDAOBgNVBAoMB1RldHJhdGUxFDASBgNVBAsM
C0VuZ2luZWVyaW5nMRAwDgYDVQQDDAd0ZXN0aW5nMFwwDQYJKoZIhvcNAQEBBQAD
SwAwSAJBAKg+Ife6c7EHqSp2jDZqBCj8dsUvUwR3pxbZdMZOHQ8JwCRLT58TFilb
HkuBMNBAG2wIBgz1yTUQD1qcCS54s8ECAwEAAaNWMFQwEgYDVR0RBAswCYIHdGVz
dGluZzAdBgNVHQ4EFgQUd/ybkK9CxV3CNd96WzNu5nbVsCgwHwYDVR0jBBgwFoAU
PZpFBk2wft5Ui/YI34+JNjPYtXgwDQYJKoZIhvcNAQELBQADQQCTPOpJQp6E6XBf
pf8oBmK4m5qM/qbReZJaRYJFaOJlvgHXkJOLW5SC++yyHLDIphn1WLDGec/Z1JYs
k3ElQddK
-----END CERTIFICATE-----`

	secondCAPem = `-----BEGIN CERTIFICATE-----
MIICMDCCAdqgAwIBAgIUae5YysWmjLQbR6SqzETNSz7EKPwwDQYJKoZIhvcNAQEL
BQAwWjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExEDAOBgNVBAoM
B1RldHJhdGUxFDASBgNVBAsMC0VuZ2luZWVyaW5nMQ4wDAYDVQQDDAVvdGhlcjAe
Fw0yNDAyMjMxMjI0NDdaFw0yNDAyMjQxMjI0NDdaMFoxCzAJBgNVBAYTAlVTMRMw
EQYDVQQIDApDYWxpZm9ybmlhMRAwDgYDVQQKDAdUZXRyYXRlMRQwEgYDVQQLDAtF
bmdpbmVlcmluZzEOMAwGA1UEAwwFb3RoZXIwXDANBgkqhkiG9w0BAQEFAANLADBI
AkEAzGmlQyy0yq6dOLNctb1L5BiQQcfN94jBtzpWavsNt1cZai592Ej7CvQ1FBUj
poP+WUOlv1puhI/sjLK1+E/cRQIDAQABo3gwdjAdBgNVHQ4EFgQU5PTjWUjpv3Hq
0Gqh7+VKX5TMJ9kwHwYDVR0jBBgwFoAU5PTjWUjpv3Hq0Gqh7+VKX5TMJ9kwEgYD
VR0TAQH/BAgwBgEB/wIBATAOBgNVHQ8BAf8EBAMCAuQwEAYDVR0RBAkwB4IFb3Ro
ZXIwDQYJKoZIhvcNAQELBQADQQCxR+vBL0fn1MeQrmla6bDYNbAkdWSJPZASbmeJ
yUoadrfNxkMnlA94OTX0wYmQ4zwedyDWRzp4HgPOWOphe2U2
-----END CERTIFICATE-----`

	secondCertPem = `-----BEGIN CERTIFICATE-----
MIICDDCCAbagAwIBAgIUZ92xILVsEMxFXr4DJLFpZXp1O5QwDQYJKoZIhvcNAQEL
BQAwWjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExEDAOBgNVBAoM
B1RldHJhdGUxFDASBgNVBAsMC0VuZ2luZWVyaW5nMQ4wDAYDVQQDDAVvdGhlcjAe
Fw0yNDAyMjMxMjI0NDdaFw0yNDAyMjQxMjI0NDdaMFoxCzAJBgNVBAYTAlVTMRMw
EQYDVQQIDApDYWxpZm9ybmlhMRAwDgYDVQQKDAdUZXRyYXRlMRQwEgYDVQQLDAtF
bmdpbmVlcmluZzEOMAwGA1UEAwwFb3RoZXIwXDANBgkqhkiG9w0BAQEFAANLADBI
AkEAnHRlTPKzGlS0xGUfgk6eQRcbc0eFlQ2QUKm55l5iBC9BP1sY5cO6jcf227l7
sFdg+9vCBa+j5whebjlWlQ5iawIDAQABo1QwUjAQBgNVHREECTAHggVvdGhlcjAd
BgNVHQ4EFgQU7l+RGBV99RiMS6FKXStwgHuBNvwwHwYDVR0jBBgwFoAU5PTjWUjp
v3Hq0Gqh7+VKX5TMJ9kwDQYJKoZIhvcNAQELBQADQQAy/TQdxLQOxYfTUsXvhbdd
CKSSTT6gHjNgrA5r61drQqvG+69zVEuWybjPzK5uSMntof6I4XWpdfWd37d7WNyd
-----END CERTIFICATE-----`
)

func TestLoadTLSConfig(t *testing.T) {
	tmpDir := t.TempDir()
	var (
		validFile   = tmpDir + "/valid.pem"
		invalidFile = tmpDir + "/invalid.pem"
	)
	require.NoError(t, os.WriteFile(validFile, []byte(firstCAPem), 0644))
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
			config:   &oidc.OIDCConfig{SkipVerifyPeerCert: structpb.NewBoolValue(true)},
			wantTLS:  true,
			wantSkip: true,
		},
		{
			name:     "valid trusted CA string config",
			config:   &oidc.OIDCConfig{TrustedCaConfig: &oidc.OIDCConfig_TrustedCertificateAuthority{TrustedCertificateAuthority: firstCAPem}},
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
		{
			name: "valid trusted CA file and skip verify config",
			config: &oidc.OIDCConfig{
				TrustedCaConfig:    &oidc.OIDCConfig_TrustedCertificateAuthorityFile{TrustedCertificateAuthorityFile: validFile},
				SkipVerifyPeerCert: structpb.NewBoolValue(true),
			},
			wantTLS:  true,
			wantSkip: false, // skip verify is ignored because there's a trusted CA
			wantPool: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			pool := NewTLSConfigPool(ctx)
			t.Cleanup(cancel)

			got, err := pool.LoadTLSConfig(tc.config)

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

func TestTLSConfigPoolUpdates(t *testing.T) {
	tmpDir := t.TempDir()
	var caFile1 = tmpDir + "/ca1.pem"
	require.NoError(t, os.WriteFile(caFile1, []byte(firstCAPem), 0644))

	block, _ := pem.Decode([]byte(firstCertPem))
	cert1, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	block, _ = pem.Decode([]byte(secondCertPem))
	cert2, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	pool := NewTLSConfigPool(ctx)
	t.Cleanup(cancel)

	const (
		interval        = 100 * time.Millisecond
		intervalAndHalf = interval + interval/2
	)

	config := &oidc.OIDCConfig{
		TrustedCaConfig: &oidc.OIDCConfig_TrustedCertificateAuthorityFile{TrustedCertificateAuthorityFile: caFile1},
		TrustedCertificateAuthorityRefreshInterval: durationpb.New(interval),
	}

	// load the TLS config
	gotTLS, err := pool.LoadTLSConfig(config)
	require.NoError(t, err)
	require.NotNil(t, gotTLS)

	// verify the got TLS config is valid
	_, err = cert1.Verify(x509.VerifyOptions{Roots: gotTLS.RootCAs, DNSName: firstCertDNSName})
	require.NoError(t, err)

	// update the CA file content
	require.NoError(t, os.WriteFile(caFile1, []byte(secondCAPem), 0644))
	time.Sleep(intervalAndHalf)

	// load the TLS config again
	gotTLS, err = pool.LoadTLSConfig(config)
	require.NoError(t, err)

	// verify the got TLS config is not valid anymore for the old CA,
	// as we updated it with CA only valid for cert2.
	_, err = cert1.Verify(x509.VerifyOptions{Roots: gotTLS.RootCAs, DNSName: firstCertDNSName})
	require.Error(t, err)

	// verify the got TLS config is valid for the new CA
	_, err = cert2.Verify(x509.VerifyOptions{Roots: gotTLS.RootCAs, DNSName: secondCertDNSName})
	require.NoError(t, err)

	// update the CA file content to be invalid
	require.NoError(t, os.WriteFile(caFile1, []byte(invalidCAPem), 0644))
	time.Sleep(intervalAndHalf)

	// load the TLS config again
	gotTLS, err = pool.LoadTLSConfig(config)
	require.NoError(t, err)

	// verify the config is not updated, so the old TLS config is still valid
	_, err = cert2.Verify(x509.VerifyOptions{Roots: gotTLS.RootCAs, DNSName: secondCertDNSName})
	require.NoError(t, err)

	// remove the CA file
	require.NoError(t, os.Remove(caFile1))
	time.Sleep(intervalAndHalf)

	// load the TLS config again
	gotTLS, err = pool.LoadTLSConfig(config)
	require.NoError(t, err)

	// verify the config is not modified, so the old TLS config is still valid
	_, err = cert2.Verify(x509.VerifyOptions{Roots: gotTLS.RootCAs, DNSName: secondCertDNSName})
	require.NoError(t, err)

	// update the CA file content to be valid again and verify the new CA is loaded
	require.NoError(t, os.WriteFile(caFile1, []byte(firstCAPem), 0644))
	time.Sleep(intervalAndHalf)

	// load the TLS config again
	gotTLS, err = pool.LoadTLSConfig(config)
	require.NoError(t, err)

	_, err = cert1.Verify(x509.VerifyOptions{Roots: gotTLS.RootCAs, DNSName: firstCertDNSName})
	require.NoError(t, err)
}

func TestTLSConfigPoolWithMultipleConfigs(t *testing.T) {
	tmpDir := t.TempDir()
	var (
		caFile1 = tmpDir + "/ca1.pem"
		caFile2 = tmpDir + "/ca2.pem"
	)
	require.NoError(t, os.WriteFile(caFile1, []byte(firstCAPem), 0644))
	require.NoError(t, os.WriteFile(caFile2, []byte(secondCAPem), 0644))

	block, _ := pem.Decode([]byte(firstCertPem))
	cert1, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	block, _ = pem.Decode([]byte(secondCertPem))
	cert2, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	pool := NewTLSConfigPool(ctx)
	t.Cleanup(cancel)

	const (
		config1Interval = 100 * time.Millisecond
		config2Interval = 200 * time.Millisecond
	)
	var intervalAndHalf = func(interval time.Duration) time.Duration { return interval + interval/2 }

	config1 := &oidc.OIDCConfig{
		TrustedCaConfig: &oidc.OIDCConfig_TrustedCertificateAuthorityFile{TrustedCertificateAuthorityFile: caFile1},
		TrustedCertificateAuthorityRefreshInterval: durationpb.New(config1Interval),
	}
	config2 := &oidc.OIDCConfig{
		TrustedCaConfig: &oidc.OIDCConfig_TrustedCertificateAuthorityFile{TrustedCertificateAuthorityFile: caFile2},
		TrustedCertificateAuthorityRefreshInterval: durationpb.New(config2Interval),
	}

	// load the TLS config for config1
	gotTLS1, err := pool.LoadTLSConfig(config1)
	require.NoError(t, err)

	// load the TLS config for config2
	gotTLS2, err := pool.LoadTLSConfig(config2)
	require.NoError(t, err)

	// verify the got TLS config for config1 is valid
	_, err = cert1.Verify(x509.VerifyOptions{Roots: gotTLS1.RootCAs, DNSName: firstCertDNSName})
	require.NoError(t, err)

	// verify the got TLS config for config2 is valid
	_, err = cert2.Verify(x509.VerifyOptions{Roots: gotTLS2.RootCAs, DNSName: secondCertDNSName})
	require.NoError(t, err)

	// update the second file to contain the first CA
	require.NoError(t, os.WriteFile(caFile2, []byte(firstCAPem), 0644))
	time.Sleep(intervalAndHalf(config2Interval))

	// load the TLS config for config2 again
	gotTLS2, err = pool.LoadTLSConfig(config2)
	require.NoError(t, err)

	// verify the got TLS config for config2 is valid for the first CA and not for the second
	_, err = cert1.Verify(x509.VerifyOptions{Roots: gotTLS2.RootCAs, DNSName: firstCertDNSName})
	require.NoError(t, err)
	_, err = cert2.Verify(x509.VerifyOptions{Roots: gotTLS2.RootCAs, DNSName: secondCertDNSName})
	require.Error(t, err)

	// verify the got TLS config for config1 is still valid
	gotTLS1, err = pool.LoadTLSConfig(config1)
	require.NoError(t, err)
	_, err = cert1.Verify(x509.VerifyOptions{Roots: gotTLS1.RootCAs, DNSName: firstCertDNSName})
	require.NoError(t, err)
}
