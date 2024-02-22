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
	"fmt"
	"os/exec"
	"strings"
	"time"
)

var (
	// DockerServiceExited is a DockerServiceStatus that matches the state "Exited"
	DockerServiceExited DockerServiceStatus = containsMatcher{"Exited"}
	// DockerServiceContainerUp is a DockerServiceStatus that matches the state "Up"
	DockerServiceContainerUp DockerServiceStatus = containsMatcher{"Up"}
	// DockerServiceContainerUpAndHealthy is a DockerServiceStatus that matches the state "Up (healthy)"
	DockerServiceContainerUpAndHealthy DockerServiceStatus = containsMatcher{"(healthy)"}
)

type (
	// DockerCompose is a helper to interact with docker compose command
	DockerCompose struct {
		log func(...any)
	}

	// DockerComposeOption is a functional option for DockerCompose initialization
	DockerComposeOption func(compose *DockerCompose)
)

// NewDockerCompose creates a new DockerCompose with the given options
func NewDockerCompose(opts ...DockerComposeOption) DockerCompose {
	d := DockerCompose{}
	d.log = NoopLogFunc // default
	for _, opt := range opts {
		opt(&d)
	}
	return d

}

// WithDockerComposeLogFunc sets the log function for the DockerCompose. The default is NoopLogFunc
func WithDockerComposeLogFunc(logFunc func(...any)) DockerComposeOption {
	return func(compose *DockerCompose) {
		compose.log = logFunc
	}
}

// NoopLogFunc is a log function that does nothing
func NoopLogFunc(...any) {}

// StartDockerService starts a docker service or returns an error
func (d DockerCompose) StartDockerService(name string) error {
	d.log("Starting docker service", name)
	out, err := exec.Command("docker", "compose", "start", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, string(out))
	}
	return nil
}

// StopDockerService stops a docker service or returns an error
func (d DockerCompose) StopDockerService(name string) error {
	d.log("Stopping docker service", name)
	out, err := exec.Command("docker", "compose", "stop", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, string(out))
	}
	return nil
}

// WaitForDockerService waits for a docker service to match a status in the given timeout or returns an error
func (d DockerCompose) WaitForDockerService(name string, status DockerServiceStatus, timeout, tick time.Duration) error {
	d.log("Waiting for docker service", name, "to match", status)
	cmd := exec.Command("docker", "compose", "ps", "-a", "--format", "{{ .Status }}", name)

	to := time.NewTimer(timeout)
	tk := time.NewTicker(tick)
	defer tk.Stop()
	defer to.Stop()

	for {
		select {
		case <-to.C:
			return fmt.Errorf("timeout waiting for service %s to match: %s", name, status)
		case <-tk.C:
			out, err := cmd.CombinedOutput()
			if err != nil {
				return fmt.Errorf("%w: %s", err, string(out))
			}
			if status.Match(string(out)) {
				d.log("Service", name, "matched", status)
				return nil
			}
		}
	}
}

type (
	// DockerServiceStatus is an interface that matches the status of a docker service
	DockerServiceStatus interface {
		// Match returns true if the status matches the given docker service status
		Match(string) bool
		// String returns a string representation of the status
		String() string
	}

	// containsMatcher is a DockerServiceStatus that matches the status if it contains a string
	containsMatcher struct {
		contains string
	}
)

// Match implements DockerServiceStatus
func (c containsMatcher) Match(out string) bool {
	return strings.Contains(out, c.contains)
}

// String implements DockerServiceStatus
func (c containsMatcher) String() string {
	return c.contains
}
