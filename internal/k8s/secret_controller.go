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

package k8s

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/tetratelabs/run"
	"github.com/tetratelabs/telemetry"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	configv1 "github.com/istio-ecosystem/authservice/config/gen/go/v1"
	oidcv1 "github.com/istio-ecosystem/authservice/config/gen/go/v1/oidc"
	"github.com/istio-ecosystem/authservice/internal"
)

var (
	_ run.PreRunner      = (*SecretController)(nil)
	_ run.ServiceContext = (*SecretController)(nil)

	ErrLoadingConfig = errors.New("error loading kube config")
)

// secretUpdateFunc is a function that updates the configuration with the loaded secret data.
type secretUpdateFunc func(ctx context.Context, secretData map[string][]byte) error

// SecretController watches secrets for updates and updates the configuration with the loaded data.
type SecretController struct {
	log              telemetry.Logger
	config           *configv1.Config
	secrets          map[string][]secretUpdateFunc
	restConf         *rest.Config
	manager          manager.Manager
	k8sClient        client.Client
	defaultNamespace string
}

// NewSecretController creates a new k8s Controller that loads secrets from
// Kubernetes and updates the configuration with the loaded data.
func NewSecretController(cfg *configv1.Config) *SecretController {
	return &SecretController{
		log:     internal.Logger(internal.Config),
		config:  cfg,
		secrets: make(map[string][]secretUpdateFunc),
	}
}

// Name implements run.PreRunner
func (s *SecretController) Name() string { return "Secret controller" }

// PreRun saves the original configuration in PreRun phase because the
// configuration is loaded from the file in the Config Validate phase.
func (s *SecretController) PreRun() error {
	if s.defaultNamespace == "" {
		var data []byte
		data, err := os.ReadFile(NamespacePath)
		if err != nil {
			s.log.Error("error reading namespace file. Defaulting to 'default' namespace",
				err, "file", NamespacePath)
			s.defaultNamespace = "default"
		} else {
			s.defaultNamespace = string(data)
		}
	}

	// Check if there are any k8s secrets to watch. By only caching the configured namespaces we don't require
	// wide permissions for the controller to watch secrets in all the namespaces.
	cachedNamespaces := s.processSecretsConfig()

	// If there are no secrets to watch, we can skip starting the controller manager
	if len(cachedNamespaces) == 0 {
		return nil
	}

	var err error

	// Load the k8s configuration from in-cluster environment
	if s.restConf == nil {
		s.restConf, err = config.GetConfig()
		if err != nil {
			return fmt.Errorf("%w: %w", ErrLoadingConfig, err)
		}
	}

	// The controller manager is encapsulated in the secret controller because we
	// only need it to watch secrets and update the configuration.
	s.manager, err = ctrl.NewManager(s.restConf, ctrl.Options{
		Metrics: metricsserver.Options{BindAddress: "0"},
		Cache: cache.Options{
			// Only watch for Secret objects in the desired namespaces
			ByObject: map[client.Object]cache.ByObject{
				&corev1.Secret{}: {Namespaces: cachedNamespaces},
			},
			DefaultTransform: cache.TransformStripManagedFields(),
		},
	})
	s.k8sClient = s.manager.GetClient()
	if err != nil {
		return fmt.Errorf("error creating controller manager: %w", err)
	}

	if err = ctrl.NewControllerManagedBy(s.manager).
		For(&corev1.Secret{}).
		Complete(s); err != nil {
		return fmt.Errorf("error creating secret controller:%w", err)
	}

	return nil
}

// processSecretsConfig reads the secrets from the configuration and registers them for updates.
func (s *SecretController) processSecretsConfig() map[string]cache.Config {
	cachedNamespaces := make(map[string]cache.Config)

	for _, c := range s.config.Chains {
		for _, f := range c.Filters {
			oidcCfg, isOIDCConf := f.Type.(*configv1.Filter_Oidc)
			if !isOIDCConf {
				continue
			}

			if ns, name := secretToWatch(oidcCfg.Oidc.GetClientSecretRef(), s.defaultNamespace); ns != "" {
				cachedNamespaces[ns] = cache.Config{}
				registerSecret(s.secrets, ns, name, updateOIDCClientSecret(s.log, ns, name, oidcCfg.Oidc))
			}
			if ns, name := secretToWatch(oidcCfg.Oidc.GetTokenExchange().GetClientCredentials().GetClientSecretRef(), s.defaultNamespace); ns != "" {
				cachedNamespaces[ns] = cache.Config{}
				registerSecret(s.secrets, ns, name, updateTokenExchangeClientSecret(s.log, ns, name, oidcCfg.Oidc.GetTokenExchange().GetClientCredentials()))
			}
		}
	}

	return cachedNamespaces
}

// ServeContext starts the controller manager and watches secrets for updates.
func (s *SecretController) ServeContext(ctx context.Context) error {
	// If there are no secrets to watch, we can skip starting the controller manager
	needWatchSecrets := len(s.secrets) != 0
	if !needWatchSecrets {
		<-ctx.Done()
		return nil
	}

	if err := s.manager.Start(ctx); err != nil {
		return fmt.Errorf("error starting controller manager: %w", err)
	}

	return nil
}

func (s *SecretController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	changedSecret := req.NamespacedName.String()
	oidcConfigsUpdateFuncs, exist := s.secrets[changedSecret]

	// If the secret is not used in the configuration, we can ignore it
	if !exist {
		return ctrl.Result{}, nil
	}

	secret := new(corev1.Secret)
	if err := s.k8sClient.Get(ctx, req.NamespacedName, secret); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if !secret.DeletionTimestamp.IsZero() {
		// Secret is being deleted, ignore it
		return ctrl.Result{}, nil
	}

	for _, oidcUpdateFunc := range oidcConfigsUpdateFuncs {
		if err := oidcUpdateFunc(ctx, secret.Data); err != nil {
			// Do not return an error here, as trying to process the secret again
			// will not help when the data is not present. Just log the error
			s.log.Error("error updating secret", err)
		}
	}

	return ctrl.Result{}, nil
}

// secretToWatch returns the namespace to watch for the given secret reference.
func secretToWatch(ref *oidcv1.OIDCConfig_SecretReference, defaultNamespace string) (string, string) {
	if ref == nil {
		return "", ""
	}
	if ref.GetNamespace() == "" {
		return defaultNamespace, ref.GetName()
	}
	return ref.GetNamespace(), ref.GetName()
}

// registerSecret registers a secret update function for the given namespace and name.
func registerSecret(secrets map[string][]secretUpdateFunc, namespace, name string, updateFn secretUpdateFunc) {
	key := namespace + "/" + name
	secrets[key] = append(secrets[key], updateFn)
}
