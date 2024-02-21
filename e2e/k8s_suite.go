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

package e2e

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	k8syamlserializer "k8s.io/apimachinery/pkg/runtime/serializer/yaml"
	"k8s.io/client-go/discovery"
	memory "k8s.io/client-go/discovery/cached"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/restmapper"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	// KubeConfig is the path where the e2e test setup generates the kubeconfig file
	KubeConfig = "cluster/kubeconfig"
	// This timeout accounts for the image pull and the pod and
	// sidecar bootstrap
	defaultServiceStartupTimeout = 5 * time.Minute
)

var (
	PodReady       = corev1.PodCondition{Type: corev1.PodReady, Status: corev1.ConditionTrue}
	PodInitialized = corev1.PodCondition{Type: corev1.PodInitialized, Status: corev1.ConditionTrue}
)

// K8sSuite is a suite that provides a Kubernetes client and a set of helper methods
// to interact with the Kubernetes API.
// Kubernetes tests can crete specific suite types that embeds this one to get access to
// the Kubernetes client and the helper methods.
type K8sSuite struct {
	suite.Suite

	Kubeconfig *rest.Config

	dynamicClient          *dynamic.DynamicClient
	discoveryClient        *discovery.DiscoveryClient
	mapper                 meta.RESTMapper
	unstructuredSerializer runtime.Serializer
}

// SetupSuite initializes the Kubernetes clients.
func (k *K8sSuite) SetupSuite() {
	cfg, err := clientcmd.BuildConfigFromFlags("", KubeConfig)
	k.Require().NoError(err)
	k.Kubeconfig = cfg

	k.dynamicClient, err = dynamic.NewForConfig(cfg)
	k.Require().NoError(err)
	k.discoveryClient, err = discovery.NewDiscoveryClientForConfig(cfg)
	k.Require().NoError(err)

	k.mapper = restmapper.NewDeferredDiscoveryRESTMapper(memory.NewMemCacheClient(k.discoveryClient))
	k.unstructuredSerializer = k8syamlserializer.NewDecodingSerializer(unstructured.UnstructuredJSONScheme)
}

// MustApply applies the given file to the Kubernetes cluster and fails the test if an error occurs.
func (k *K8sSuite) MustApply(ctx context.Context, file string) {
	k.Require().NoError(k.Apply(ctx, file))
}

// Apply the given file to the Kubernetes cluster.
func (k *K8sSuite) Apply(ctx context.Context, file string) error {
	var errs []error
	for _, o := range k.ReadObjects(file) {
		_, err := k.dynamicClientFor(o).Apply(ctx, o.GetName(), o, metav1.ApplyOptions{FieldManager: "e2e"})
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// MustDelete deletes the resources defined in the given file from the Kubernetes cluster and fails
// the test if an error occurs.
func (k *K8sSuite) MustDelete(ctx context.Context, file string) {
	k.Require().NoError(k.Delete(ctx, file))
}

// Delete the resources defined in the given file from the Kubernetes cluster.
func (k *K8sSuite) Delete(ctx context.Context, file string) error {
	var (
		errs []error
		objs = k.ReadObjects(file)
	)

	for i := len(objs) - 1; i >= 0; i-- {
		o := objs[i]
		if err := k.dynamicClientFor(o).Delete(ctx, o.GetName(), metav1.DeleteOptions{}); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// ReadObjects reads the given file and returns the list of Kubernetes objects defined in it.
func (k *K8sSuite) ReadObjects(file string) []*unstructured.Unstructured {
	content, err := os.ReadFile(file)
	k.Require().NoError(err)

	out := make([]*unstructured.Unstructured, 0)
	dec := yaml.NewDecoder(bytes.NewReader(content))

	for {
		var node yaml.Node
		err := dec.Decode(&node)
		if errors.Is(err, io.EOF) {
			break
		}
		k.Require().NoError(err)

		content, err := yaml.Marshal(&node)
		k.Require().NoError(err)

		obj := &unstructured.Unstructured{}
		_, _, err = k.unstructuredSerializer.Decode(content, nil, obj)
		k.Require().NoError(err)

		out = append(out, obj)
	}

	return out
}

// dynamicClientFor returns a dynamic client for the given object.
func (k *K8sSuite) dynamicClientFor(obj *unstructured.Unstructured) dynamic.ResourceInterface {
	gvk := obj.GetObjectKind().GroupVersionKind()
	mapping, err := k.mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
	k.Require().NoError(err)

	var dr dynamic.ResourceInterface
	if mapping.Scope.Name() == meta.RESTScopeNameNamespace {
		dr = k.dynamicClient.Resource(mapping.Resource).Namespace(obj.GetNamespace())
	} else {
		dr = k.dynamicClient.Resource(mapping.Resource)
	}

	return dr
}

// WaitForPods waits for the pods in the given namespace and with the given selector
// to be in the given phase and condition.
func (k *K8sSuite) WaitForPods(client kubernetes.Interface, namespace, selector string, phase corev1.PodPhase, condition corev1.PodCondition) {
	k.T().Logf("waiting for %s/[%s] to be %v...", namespace, selector, phase)

	require.Eventually(k.T(), func() bool {
		opts := metav1.ListOptions{
			LabelSelector: selector,
		}
		pods, err := client.CoreV1().Pods(namespace).List(context.Background(), opts)
		if err != nil || len(pods.Items) == 0 {
			return false
		}

	checkPods:
		for _, p := range pods.Items {
			if p.Status.Phase != phase {
				return false
			}

			if p.Status.Conditions == nil {
				return false
			}

			for _, c := range p.Status.Conditions {
				if c.Type == condition.Type && c.Status == condition.Status {
					continue checkPods // pod is ready, check next pod
				}
			}

			return false
		}

		return true
	}, defaultServiceStartupTimeout, 2*time.Second)
}
