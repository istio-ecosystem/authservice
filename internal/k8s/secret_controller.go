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
	"k8s.io/apimachinery/pkg/types"
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

const clientSecretKey = "client-secret"

var (
	_ run.PreRunner      = (*SecretController)(nil)
	_ run.ServiceContext = (*SecretController)(nil)

	ErrLoadingConfig           = errors.New("error loading kube config")
	ErrCrossNamespaceSecretRef = errors.New("cross-namespace secret reference is not allowed")
)

// SecretController watches secrets for updates and updates the configuration with the loaded data.
type SecretController struct {
	log       telemetry.Logger
	config    *configv1.Config
	secrets   map[string][]func(string, []byte)
	restConf  *rest.Config
	manager   manager.Manager
	k8sClient client.Client
	namespace string
}

// NewSecretController creates a new k8s Controller that loads secrets from
// Kubernetes and updates the configuration with the loaded data.
func NewSecretController(cfg *configv1.Config) *SecretController {
	return &SecretController{
		log:    internal.Logger(internal.Config),
		config: cfg,
	}
}

// Name implements run.PreRunner
func (s *SecretController) Name() string { return "Secret controller" }

// PreRun saves the original configuration in PreRun phase because the
// configuration is loaded from the file in the Config Validate phase.
func (s *SecretController) PreRun() error {
	var (
		needWatchSecrets = false
		err              error
	)

	// Check if there are any k8s secrets to watch
	for _, c := range s.config.Chains {
		for _, f := range c.Filters {
			oidcCfg, isOIDCConf := f.Type.(*configv1.Filter_Oidc)
			if isOIDCConf &&
				(oidcCfg.Oidc.GetClientSecretRef() != nil || oidcCfg.Oidc.GetTokenExchange().GetClientCredentials().GetClientSecretRef() != nil) {
				needWatchSecrets = true
				break
			}
		}
	}

	// If there are no secrets to watch, we can skip starting the controller manager
	if !needWatchSecrets {
		return nil
	}

	// Load the current namespace from the service account directory
	if s.namespace == "" {
		var data []byte
		data, err = os.ReadFile(NamespacePath)
		if err != nil {
			return fmt.Errorf("error reading namespace file %s: %w", NamespacePath, err)
		}
		s.namespace = string(data)
	}

	// Collect the k8s secrets that are used in the configuration
	if err = s.loadSecrets(); err != nil {
		return err
	}

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
			// Only watch for Secret objects in the desired namespace and ignore the rest
			ByObject: map[client.Object]cache.ByObject{
				&corev1.Secret{}: {Namespaces: map[string]cache.Config{s.namespace: {}}},
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

// loadSecrets loads the secrets from the configuration and stores them in the secrets map.
func (s *SecretController) loadSecrets() error {
	s.secrets = make(map[string][]func(string, []byte))
	for _, c := range s.config.Chains {
		for _, f := range c.Filters {
			oidcCfg, isOIDCConf := f.Type.(*configv1.Filter_Oidc)
			if !isOIDCConf {
				continue
			}

			if err := loadSecret(s.secrets, oidcCfg.Oidc.GetClientSecretRef(), s.namespace,
				func(name string, v []byte) {
					s.log.Info("updating client-secret data from secret", "secret", name, "client-id", oidcCfg.Oidc.GetClientId())
					oidcCfg.Oidc.ClientSecretConfig = &oidcv1.OIDCConfig_ClientSecret{
						ClientSecret: string(v),
					}
				}); err != nil {
				return err
			}
			if err := loadSecret(s.secrets, oidcCfg.Oidc.GetTokenExchange().GetClientCredentials().GetClientSecretRef(), s.namespace,
				func(name string, v []byte) {
					s.log.Info("updating token exchange client-secret data from secret",
						"secret", name, "client-id", oidcCfg.Oidc.TokenExchange.GetClientCredentials().GetClientId())
					oidcCfg.Oidc.TokenExchange.GetClientCredentials().ClientSecretConfig = &oidcv1.OIDCConfig_TokenExchange_ClientCredentials_ClientSecret{
						ClientSecret: string(v),
					}
				}); err != nil {
				return err
			}
		}
	}
	return nil
}

func loadSecret(secrets map[string][]func(string, []byte), ref *oidcv1.OIDCConfig_SecretReference, namespace string, updateFn func(string, []byte)) error {
	if ref == nil || ref.GetName() == "" {
		return nil // No secret reference to load
	}
	if ref.Namespace != "" && ref.Namespace != namespace {
		return fmt.Errorf("%w: secret reference namespace %s does not match the current namespace %s",
			ErrCrossNamespaceSecretRef, ref.Namespace, namespace)
	}
	key := secretNamespacedName(ref, namespace).String()
	secrets[key] = append(secrets[key], updateFn)
	return nil
}

func secretNamespacedName(secretRef *oidcv1.OIDCConfig_SecretReference, currentNamespace string) types.NamespacedName {
	return types.NamespacedName{
		Namespace: currentNamespace,
		Name:      secretRef.GetName(),
	}
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

	clientSecretBytes, ok := secret.Data[clientSecretKey]
	if !ok || len(clientSecretBytes) == 0 {
		s.log.Error("", errors.New("client-secret not found in secret"), "secret", changedSecret)
		// Do not return an error here, as trying to process the secret again
		// will not help when the data is not present.
		return ctrl.Result{}, nil
	}

	for _, oidcUpdateFunc := range oidcConfigsUpdateFuncs {
		oidcUpdateFunc(secret.GetName(), clientSecretBytes)
	}

	return ctrl.Result{}, nil
}
