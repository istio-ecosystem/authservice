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

package k8s

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	configv1 "github.com/tetrateio/authservice-go/config/gen/go/v1"
)

func TestOIDCProcessWithKubernetesSecret(t *testing.T) {
	tests := []struct {
		name     string
		testFile string
		err      error
	}{
		{"multiple secret refs", "oidc-with-multiple-secret-refs", nil},
		{"no secret ref", "oidc-without-secret-ref", nil},
		{"secret ref without data", "oidc-with-secret-ref-without-data", nil},
		{"secret ref deleting", "oidc-with-secret-ref-deleting", nil},
		{"secret ref not found", "oidc-with-secret-ref-not-found", nil},
		{"cross namespace secret ref", "oidc-with-cross-ns-secret-ref", ErrCrossNamespaceSecretRef},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// load test data
			originalConf := loadTestConf(t, fmt.Sprintf("testdata/%s-in.json", tt.testFile))
			expectedConf := loadTestConf(t, fmt.Sprintf("testdata/%s-out.json", tt.testFile))

			// create secret controller
			secrets := secretsForTest()
			kubeClient := fake.NewClientBuilder().WithLists(secrets).Build()
			controller := NewSecretController(originalConf)
			controller.namespace = "default"
			controller.k8sClient = kubeClient // set the k8s client with the fake client for testing
			require.ErrorIs(t, controller.loadSecrets(), tt.err)

			// reconcile the secrets
			for _, secret := range secrets.Items {
				_, err := controller.Reconcile(context.Background(), ctrl.Request{
					NamespacedName: types.NamespacedName{
						Namespace: secret.Namespace,
						Name:      secret.Name,
					},
				})
				require.NoError(t, err)
			}
			_, err := controller.Reconcile(context.Background(), ctrl.Request{
				NamespacedName: types.NamespacedName{
					Namespace: "default",
					Name:      "non-existing-secret",
				},
			})
			require.NoError(t, err)

			// check if the configuration is updated
			require.True(t, proto.Equal(originalConf, expectedConf))
		})
	}
}

func secretsForTest() *corev1.SecretList {
	return &corev1.SecretList{
		Items: []corev1.Secret{
			{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "test-secret-1",
				},
				Data: map[string][]byte{
					clientSecretKey: []byte("fake-client-secret-1"),
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "test-secret-2",
				},
				Data: map[string][]byte{
					clientSecretKey: []byte("fake-client-secret-2"),
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "test-secret-without-data",
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:         "default",
					Name:              "test-secret-deleting",
					DeletionTimestamp: &metav1.Time{Time: time.Now()},
					Finalizers:        []string{"kubernetes"},
				},
			},
		},
	}
}

func loadTestConf(t *testing.T, file string) *configv1.Config {
	var conf = &configv1.Config{}
	content, err := os.ReadFile(file)
	require.NoError(t, err)
	err = protojson.Unmarshal(content, conf)
	require.NoError(t, err)
	return conf
}
