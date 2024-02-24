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
	"errors"
	"fmt"

	"github.com/tetratelabs/run"
	"github.com/tetratelabs/telemetry"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"

	configv1 "github.com/tetrateio/authservice-go/config/gen/go/v1"
	oidcv1 "github.com/tetrateio/authservice-go/config/gen/go/v1/oidc"
)

const (
	defaultNamespace = "default"
	clientSecretKey  = "client-secret"
)

var (
	_ run.PreRunner = (*SecretLoader)(nil)

	ErrLoadingKubeConfig = errors.New("error loading kube config")
	ErrGetSecret         = errors.New("err getting secret")
	ErrNoSecretData      = errors.New("client-secret not found in secret")
)

// SecretLoader is a pre-runner that loads secrets from Kubernetes and updates
// the configuration with the loaded data.
type SecretLoader struct {
	log       telemetry.Logger
	cfg       *configv1.Config
	k8sClient client.Client
}

// NewSecretLoader creates a new that loads secrets from Kubernetes and updates
// // the configuration with the loaded data.
func NewSecretLoader(cfg *configv1.Config) *SecretLoader {
	return &SecretLoader{
		log: Logger(Config),
		cfg: cfg,
	}
}

// Name implements run.PreRunner
func (s *SecretLoader) Name() string { return "Secret loader" }

// PreRun processes all the OIDC configurations and loads all required secrets from Kubernetes.
func (s *SecretLoader) PreRun() error {
	var errs []error
	for _, c := range s.cfg.Chains {
		for _, f := range c.Filters {
			oidcCfg, ok := f.Type.(*configv1.Filter_Oidc)
			if !ok || oidcCfg.Oidc.GetClientSecretRef().GetName() == "" {
				continue
			}

			if s.k8sClient == nil {
				var err error
				s.k8sClient, err = getKubeClient()
				if err != nil {
					return fmt.Errorf("%w: loading client secret from k8s:  %w", ErrLoadingKubeConfig, err)
				}
			}

			errs = append(errs, s.loadClientSecretFromK8s(oidcCfg.Oidc))
		}
	}

	return errors.Join(errs...)
}

// loadClientSecretFromK8s retrieves the client secret from the referenced Kubernetes secret.
func (s *SecretLoader) loadClientSecretFromK8s(cfg *oidcv1.OIDCConfig) error {
	namespace := cfg.GetClientSecretRef().Namespace
	if namespace == "" {
		namespace = defaultNamespace
	}
	secretName := types.NamespacedName{
		Namespace: namespace,
		Name:      cfg.GetClientSecretRef().GetName(),
	}

	s.log.Info("loading client-secret from secret",
		"secret", secretName.String(), "client-id", cfg.GetClientId())

	secret := &corev1.Secret{}
	if err := s.k8sClient.Get(context.Background(), secretName, secret); err != nil {
		return fmt.Errorf("%w: %w", ErrGetSecret, err)
	}

	clientSecretBytes, ok := secret.Data[clientSecretKey]
	if !ok || len(clientSecretBytes) == 0 {
		return fmt.Errorf("%w: %s", ErrNoSecretData, secretName.String())
	}

	// Update the configuration with the loaded client secret
	cfg.ClientSecretConfig = &oidcv1.OIDCConfig_ClientSecret{
		ClientSecret: string(clientSecretBytes),
	}

	return nil
}

// getKubeClient returns a new Kubernetes client used to load secrets.
func getKubeClient() (client.Client, error) {
	cfg, err := config.GetConfig()
	if err != nil {
		return nil, fmt.Errorf("error getting kube config: %w", err)
	}

	cl, err := client.New(cfg, client.Options{})
	if err != nil {
		return nil, fmt.Errorf("errot creating kube client: %w", err)
	}

	return cl, nil
}
