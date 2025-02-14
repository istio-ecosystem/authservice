// Copyright 2025 Tetrate
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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/istio-ecosystem/authservice/config/gen/go/v1/oidc"
)

const (
	invalidCAPem      = `<invalid ca.pem>`
	firstCertDNSName  = "first"
	secondCertDNSName = "second"
)

func TestLoadTLSConfig(t *testing.T) {
	tmpDir := t.TempDir()
	var (
		validFile     = tmpDir + "/valid.pem"
		invalidFile   = tmpDir + "/invalid.pem"
		firstCAPem, _ = genCAAndCert(t, firstCertDNSName)
	)
	require.NoError(t, os.WriteFile(validFile, firstCAPem, 0644))
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
			config:   &oidc.OIDCConfig{TrustedCaConfig: &oidc.OIDCConfig_TrustedCertificateAuthority{TrustedCertificateAuthority: string(firstCAPem)}},
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
	firstCAPem, firstCertPem := genCAAndCert(t, firstCertDNSName)
	secondCAPem, secondCertPem := genCAAndCert(t, secondCertDNSName)

	tmpDir := t.TempDir()
	var caFile1 = tmpDir + "/ca1.pem"
	require.NoError(t, os.WriteFile(caFile1, firstCAPem, 0644))

	block, _ := pem.Decode(firstCertPem)
	cert1, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	block, _ = pem.Decode(secondCertPem)
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
	require.NoError(t, os.WriteFile(caFile1, secondCAPem, 0644))
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
	require.NoError(t, os.WriteFile(caFile1, firstCAPem, 0644))
	time.Sleep(intervalAndHalf)

	// load the TLS config again
	gotTLS, err = pool.LoadTLSConfig(config)
	require.NoError(t, err)

	_, err = cert1.Verify(x509.VerifyOptions{Roots: gotTLS.RootCAs, DNSName: firstCertDNSName})
	require.NoError(t, err)
}

func TestTLSConfigPoolWithMultipleConfigs(t *testing.T) {
	var (
		tmpDir = t.TempDir()

		firstCAPem, firstCertPem   = genCAAndCert(t, firstCertDNSName)
		secondCAPem, secondCertPem = genCAAndCert(t, secondCertDNSName)

		caFile1 = tmpDir + "/ca1.pem"
		caFile2 = tmpDir + "/ca2.pem"
	)
	require.NoError(t, os.WriteFile(caFile1, firstCAPem, 0644))
	require.NoError(t, os.WriteFile(caFile2, secondCAPem, 0644))

	block, _ := pem.Decode(firstCertPem)
	cert1, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	block, _ = pem.Decode(secondCertPem)
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
	require.NoError(t, os.WriteFile(caFile2, firstCAPem, 0644))
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

func genCAAndCert(t *testing.T, dnsName string) ([]byte, []byte) {
	defaultSubject := pkix.Name{
		Organization: []string{"Tetrate"},
		Country:      []string{"US"},
		Locality:     []string{"San Francisco"},
	}

	caKey, err := rsa.GenerateKey(rand.Reader, 4096)
	require.NoError(t, err)

	ca := x509.Certificate{
		SerialNumber:          big.NewInt(2025),
		Subject:               defaultSubject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * time.Minute),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, &ca, &ca, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber:          big.NewInt(2025),
		Subject:               defaultSubject,
		DNSNames:              []string{dnsName},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(5 * time.Minute),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certKey, err := rsa.GenerateKey(rand.Reader, 4096)
	require.NoError(t, err)

	der, err := x509.CreateCertificate(rand.Reader, &template, &ca, &certKey.PublicKey, caKey)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
