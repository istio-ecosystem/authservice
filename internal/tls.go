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
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"sync"

	"github.com/tetratelabs/telemetry"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"
)

type (
	// TLSConfig is an interface for the TLS configuration of the AuthService.
	TLSConfig interface {
		// GetTrustedCertificateAuthority returns the trusted certificate authority PEM.
		GetTrustedCertificateAuthority() string
		// GetTrustedCertificateAuthorityFile returns the path to the trusted certificate authority file.
		GetTrustedCertificateAuthorityFile() string
		// GetSkipVerifyPeerCert returns whether to skip verification of the peer certificate.
		GetSkipVerifyPeerCert() *structpb.Value
		GetTrustedCertificateAuthorityRefreshInterval() *durationpb.Duration
	}

	// TLSConfigPool is an interface for a pool of TLS configurations.
	TLSConfigPool interface {
		// LoadTLSConfig loads a TLS configuration from the given TLSConfig.
		LoadTLSConfig(config TLSConfig) (*tls.Config, error)
	}

	// tlsConfigPool is a pool of TLS configurations.
	// That reloads the trusted certificate authority when there are changes.
	tlsConfigPool struct {
		ctx    context.Context
		cancel context.CancelFunc
		log    telemetry.Logger

		mu        sync.RWMutex
		configs   map[string]*tls.Config
		caWatcher *FileWatcher
	}
)

// NewTLSConfigPool creates a new TLSConfigPool.
func NewTLSConfigPool(ctx context.Context) TLSConfigPool {
	ctx, cancel := context.WithCancel(ctx)
	return &tlsConfigPool{
		ctx:       ctx,
		cancel:    cancel,
		log:       Logger(Config),
		configs:   make(map[string]*tls.Config),
		caWatcher: NewFileWatcher(ctx),
	}
}

// LoadTLSConfig loads a TLS configuration from the given TLSConfig.
func (p *tlsConfigPool) LoadTLSConfig(config TLSConfig) (*tls.Config, error) {
	encConfig := encodeConfig(config)
	id := encConfig.hash()
	if tlsConfig, ok := p.configs[id]; ok {
		return tlsConfig, nil
	}

	log := p.log.With("id", id)
	log.Info("loading new TLS config", "config", encConfig.JSON())
	tlsConfig := &tls.Config{}

	// Load the trusted CA PEM from the config
	var ca []byte
	switch {
	case config.GetTrustedCertificateAuthority() != "":
		ca = []byte(config.GetTrustedCertificateAuthority())

	case config.GetTrustedCertificateAuthorityFile() != "":
		var err error
		ca, err = p.caWatcher.WatchFile(
			NewFileReader(config.GetTrustedCertificateAuthorityFile()),
			config.GetTrustedCertificateAuthorityRefreshInterval().AsDuration(),
			func(data []byte) { p.updateCA(id, data) },
		)
		if err != nil {
			return nil, fmt.Errorf("error watching trusted CA file: %w", err)
		}

	case config.GetSkipVerifyPeerCert() != nil:
		tlsConfig.InsecureSkipVerify = BoolStrValue(config.GetSkipVerifyPeerCert())

	default:
		// No CA or skip verification, return nil TLS config
		return nil, nil
	}

	// Add the loaded CA to the TLS config
	if len(ca) != 0 {
		if BoolStrValue(config.GetSkipVerifyPeerCert()) {
			log.Info("`skip_verify_peer_cert` is set to true but there's also a trusted certificate authority, ignoring `skip_verify_peer_cert`")
		}

		certPool, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("error creating system cert pool: %w", err)
		}

		if ok := certPool.AppendCertsFromPEM(ca); !ok {
			return nil, errors.New("could no load trusted certificate authority")
		}

		tlsConfig.RootCAs = certPool
	}

	// Save the TLS config to the pool
	p.mu.Lock()
	p.configs[id] = tlsConfig
	p.mu.Unlock()
	return tlsConfig, nil
}

func (p *tlsConfigPool) updateCA(id string, caPem []byte) {
	log := p.log.With("id", id)

	// Load the TLS config
	p.mu.Lock()
	tlsConfig, ok := p.configs[id]
	if !ok {
		log.Error("couldn't update TLS config", errors.New("config not found"))
		p.mu.Unlock()
		return
	}
	p.mu.Unlock()

	// Add the loaded CA to the TLS config
	certPool, err := x509.SystemCertPool()
	if err != nil {
		log.Error("error creating system cert pool", err)
		return
	}

	if ok := certPool.AppendCertsFromPEM(caPem); !ok {
		log.Error("could not load trusted certificate authority", errors.New("failed to append certificate in the cert pool"))
		return
	}

	// Update the TLS config
	tlsConfig.RootCAs = certPool
	log.Info("updated TLS config with new trusted certificate authority")

	p.mu.Lock()
	p.configs[id] = tlsConfig
	p.mu.Unlock()
}

// tlsConfigEncoder is the internal representation of a TLSConfig.
// It handles some useful methods for the TLSConfig.
type tlsConfigEncoder struct {
	SkipVerifyPeerCert       bool   `json:"skipVerifyPeerCert,omitempty"`
	TrustedCA                string `json:"trustedCertificateAuthority,omitempty"`
	TrustedCAFile            string `json:"trustedCertificateAuthorityFile,omitempty"`
	TrustedCARefreshInterval string `json:"trustedCertificateAuthorityRefreshInterval,omitempty"`
}

// encodeConfig converts a TLSConfig to an tlsConfigEncoder.
func encodeConfig(config TLSConfig) tlsConfigEncoder {
	return tlsConfigEncoder{
		TrustedCA:                config.GetTrustedCertificateAuthority(),
		TrustedCAFile:            config.GetTrustedCertificateAuthorityFile(),
		TrustedCARefreshInterval: config.GetTrustedCertificateAuthorityRefreshInterval().AsDuration().String(),
		SkipVerifyPeerCert:       BoolStrValue(config.GetSkipVerifyPeerCert()),
	}
}

// hash returns the hash of the tls config.
func (c tlsConfigEncoder) hash() string {
	buff := bytes.Buffer{}
	_, _ = buff.WriteString(fmt.Sprintf("%t", c.SkipVerifyPeerCert))
	_, _ = buff.WriteString(c.TrustedCA)
	_, _ = buff.WriteString(c.TrustedCAFile)
	_, _ = buff.WriteString(c.TrustedCARefreshInterval)
	hash := fnv.New64a()
	_, _ = hash.Write(buff.Bytes())
	out := hash.Sum(make([]byte, 0, 15))
	return hex.EncodeToString(out)
}

// JSON returns the JSON representation of the tls config.
func (c tlsConfigEncoder) JSON() string {
	jsonBytes, _ := json.Marshal(c)
	return string(jsonBytes)
}
