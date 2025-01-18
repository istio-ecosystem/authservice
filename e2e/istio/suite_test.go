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

package istio

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/suite"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/istio-ecosystem/authservice/e2e"
)

const (
	istioHelmRepo = "https://istio-release.storage.googleapis.com/charts"
	istiodConfig  = "cluster/istiod-config.yaml"
	istioGwConfig = "cluster/istiogw-config.yaml"
	manifestsDir  = "cluster/manifests"
)

// testManifests contains the list of manifests that will be deployed in the cluster before running the e2e tests
var testManifests = []string{
	"keycloak.yaml",
	"redis.yaml",
	"authservice.yaml",
	"http-echo.yaml",
	"ingress-gateway.yaml",
	"authz-policy.yaml",
	"telemetry.yaml",
}

// IstioSuite is a suite that installs Istio in the Kubernetes cluster and runs tests against it.
type IstioSuite struct {
	e2e.K8sSuite
	IstioVersion       string
	IstioConfigValues  string
	IstioGatewayValues string
}

func TestIstio(t *testing.T) {
	suite.Run(t, &IstioSuite{
		// If the IstioVersion is empty, the latest version will be installed
		IstioVersion:       os.Getenv("E2E_ISTIO_VERSION"),
		IstioConfigValues:  istiodConfig,
		IstioGatewayValues: istioGwConfig,
	})
}

// SetupSuite initializes the Kubernetes clients, installs Istio in the cluster and waits until the
// services are up and running.
func (i *IstioSuite) SetupSuite() {
	i.K8sSuite.SetupSuite()

	client, err := kubernetes.NewForConfig(i.Kubeconfig)
	i.Require().NoError(err)

	// If Istio is already installed, just return and do not try to install it again
	// and make e2e tests easier to run multiple times without tearing down the entire
	// environment
	if !i.istioInstalled(client) {
		i.installIstio()
	}

	i.T().Log("deploying the test services...")
	for _, f := range testManifests {
		i.MustApply(context.Background(), manifestsDir+"/"+f)
	}
	i.WaitForPods(client, "keycloak", "job-name=setup-keycloak", corev1.PodSucceeded, e2e.PodInitialized)
	i.WaitForPods(client, "redis", "", corev1.PodRunning, e2e.PodReady)
	i.WaitForPods(client, "authservice", "", corev1.PodRunning, e2e.PodReady)
	i.WaitForPods(client, "http-echo", "", corev1.PodRunning, e2e.PodReady)
}

func (i *IstioSuite) installIstio() {
	if i.IstioVersion == "" {
		i.T().Log("installing Istio (latest)...")
	} else {
		i.T().Logf("installing Istio %s...", i.IstioVersion)
	}

	var istioInstall = []string{
		fmt.Sprintf("helm repo add istio %s --force-update", istioHelmRepo),
		"helm repo update istio",
		i.helmInstall("istio-base", "istio/base", ""),
		i.helmInstall("istiod", "istio/istiod", istiodConfig),
		i.helmInstall("istio-ingress", "istio/gateway", istioGwConfig),
	}

	for _, cmd := range istioInstall {
		parts := strings.Split(cmd, " ")
		out, err := exec.Command(parts[0], parts[1:]...).CombinedOutput()
		i.Require().NoError(err, string(out))
	}
}

func (i *IstioSuite) istioInstalled(client kubernetes.Interface) bool {
	_, err := client.CoreV1().Services("istio-system").Get(context.Background(), "istiod", metav1.GetOptions{})
	return err == nil
}

func (i *IstioSuite) helmInstall(name, chart, values string) string {
	cmd := fmt.Sprintf("helm --kubeconfig %s install %s %s --version %s -n istio-system --create-namespace --wait",
		e2e.KubeConfig, name, chart, i.IstioVersion)
	if values != "" {
		cmd += fmt.Sprintf(" -f %s", values)
	}
	return cmd
}
