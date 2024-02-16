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
	"errors"
	"fmt"
	"net/url"
	"os"

	"github.com/redis/go-redis/v9"
	"github.com/tetratelabs/run"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	configv1 "github.com/tetrateio/authservice-go/config/gen/go/v1"
	oidcv1 "github.com/tetrateio/authservice-go/config/gen/go/v1/oidc"
)

var (
	_ run.Config = (*LocalConfigFile)(nil)

	ErrInvalidPath         = errors.New("invalid path")
	ErrInvalidOIDCOverride = errors.New("invalid OIDC override")
	ErrDuplicateOIDCConfig = errors.New("duplicate OIDC configuration")
	ErrMultipleOIDCConfig  = errors.New("multiple OIDC configurations")
	ErrInvalidURL          = errors.New("invalid URL")
	ErrRequiredURL         = errors.New("required URL")
	ErrHealthPortInUse     = errors.New("health port is already in use by listen port")
)

// LocalConfigFile is a run.Config that loads the configuration file.
type LocalConfigFile struct {
	path   string
	Config configv1.Config
}

// Name returns the name of the unit in the run.Group.
func (l *LocalConfigFile) Name() string { return "Local configuration file" }

// FlagSet returns the flags used to customize the config file location.
func (l *LocalConfigFile) FlagSet() *run.FlagSet {
	flags := run.NewFlagSet("Local Config File flags")
	flags.StringVar(&l.path, "config-path", "/etc/authservice/config.json", "configuration file path")
	return flags
}

// Validate and load the configuration file.
func (l *LocalConfigFile) Validate() error {
	if l.path == "" {
		return ErrInvalidPath
	}

	content, err := os.ReadFile(l.path)
	if err != nil {
		return err
	}

	if err = protojson.Unmarshal(content, &l.Config); err != nil {
		return err
	}

	if l.Config.GetListenPort() == l.Config.GetHealthListenPort() {
		return ErrHealthPortInUse
	}

	// Validate the URLs before merging the OIDC configurations
	if err = validateURLs(&l.Config); err != nil {
		return err
	}

	// Validate OIDC configuration overrides
	for _, fc := range l.Config.Chains {
		hasOidc := false
		for _, f := range fc.Filters {
			if l.Config.DefaultOidcConfig != nil && f.GetOidc() != nil {
				return fmt.Errorf("%w: in chain %q OIDC filter and default OIDC configuration cannot be used together",
					ErrDuplicateOIDCConfig, fc.Name)
			}
			if l.Config.DefaultOidcConfig == nil && f.GetOidcOverride() != nil {
				return fmt.Errorf("%w: in chain %q OIDC override filter requires a default OIDC configuration",
					ErrInvalidOIDCOverride, fc.Name)
			}
			if f.GetOidc() != nil || f.GetOidcOverride() != nil {
				if hasOidc {
					return fmt.Errorf("%w: ionly one OIDC configuration is allowed in a chain", ErrMultipleOIDCConfig)
				}
				hasOidc = true
			}
		}
	}

	// Overrides for non-supported values
	l.Config.Threads = 1

	// Merge the OIDC overrides with the default OIDC configuration so that
	// we can properly validate the settings and  all filters have only one
	// location where the OIDC configuration is defined.
	if err = mergeAndValidateOIDCConfigs(&l.Config); err != nil {
		return err
	}

	// Now that all defaults are set and configurations are merged, validate all final settings
	return l.Config.ValidateAll()
}

// mergeAndValidateOIDCConfigs merges the OIDC overrides with the default OIDC configuration so that
// all filters have only one location where the OIDC configuration is defined.
func mergeAndValidateOIDCConfigs(cfg *configv1.Config) error {
	var errs []error

	for _, fc := range cfg.Chains {
		for _, f := range fc.Filters {
			if _, ok := f.Type.(*configv1.Filter_Mock); ok {
				continue
			}

			// Merge the OIDC overrides and populate the normal OIDC field instead so that
			// consumers of the config always have an up-to-date object
			if f.GetOidcOverride() != nil {
				oidc := proto.Clone(cfg.DefaultOidcConfig).(*oidcv1.OIDCConfig)
				proto.Merge(oidc, f.GetOidcOverride())
				f.Type = &configv1.Filter_Oidc{Oidc: oidc}
			}

			if f.GetOidc().GetConfigurationUri() == "" {
				if f.GetOidc().GetAuthorizationUri() == "" {
					errs = append(errs, fmt.Errorf("%w: missing authorization URI in chain %q", ErrRequiredURL, fc.Name))
				}
				if f.GetOidc().GetTokenUri() == "" {
					errs = append(errs, fmt.Errorf("%w: missing token URI in chain %q", ErrRequiredURL, fc.Name))
				}
				if f.GetOidc().GetJwks() == "" && f.GetOidc().GetJwksFetcher().GetJwksUri() == "" {
					errs = append(errs, fmt.Errorf("%w: missing JWKS URI  in chain %q", ErrRequiredURL, fc.Name))
				}
			}
		}
	}
	// Clear the default config as it has already been merged. This way there is only one
	// location for the OIDC settings.
	cfg.DefaultOidcConfig = nil

	return errors.Join(errs...)
}

func ConfigToJSONString(c *configv1.Config) string {
	b, _ := protojson.Marshal(c)
	return string(b)
}

func validateURLs(config *configv1.Config) error {
	if err := validateOIDCConfigURLs(config.DefaultOidcConfig); err != nil {
		return fmt.Errorf("invalid default OIDC config: %w", err)
	}

	for _, fc := range config.Chains {
		for fi, f := range fc.Filters {
			if f.GetOidc() != nil {
				err := validateOIDCConfigURLs(f.GetOidc())
				if err != nil {
					return fmt.Errorf("invalid OIDC config from chain[%s].filter[%d]: %w", fc.GetName(), fi, err)
				}
			}
			if f.GetOidcOverride() != nil {
				err := validateOIDCConfigURLs(f.GetOidcOverride())
				if err != nil {
					return fmt.Errorf("invalid OIDC override from chain[%s].filter[%d]: %w", fc.GetName(), fi, err)
				}
			}
		}
	}

	return nil
}

func validateOIDCConfigURLs(c *oidcv1.OIDCConfig) error {
	if err := validateURL(c.GetProxyUri()); err != nil {
		return fmt.Errorf("%w: invalid proxy URL: %w", ErrInvalidURL, err)
	}
	if err := validateURL(c.GetTokenUri()); err != nil {
		return fmt.Errorf("%w: invalid token URL: %w", ErrInvalidURL, err)
	}
	if err := validateURL(c.GetConfigurationUri()); err != nil {
		return fmt.Errorf("%w: invalid configuration URL: %w", ErrInvalidURL, err)
	}
	if err := validateURL(c.GetAuthorizationUri()); err != nil {
		return fmt.Errorf("%w: invalid authorization URL: %w", ErrInvalidURL, err)
	}
	if err := validateURL(c.GetCallbackUri()); err != nil {
		return fmt.Errorf("%w: invalid callback URL: %w", ErrInvalidURL, err)
	}
	if err := validateURL(c.GetJwksFetcher().GetJwksUri()); err != nil {
		return fmt.Errorf("%w: invalid JWKS Fetcher URL: %w", ErrInvalidURL, err)
	}
	if redisURL := c.GetRedisSessionStoreConfig().GetServerUri(); redisURL != "" {
		if _, err := redis.ParseURL(redisURL); err != nil {
			return fmt.Errorf("%w: invalid Redis session store URL: %w", ErrInvalidURL, err)
		}
	}
	return nil
}

func validateURL(u string) error {
	if u == "" {
		return nil
	}
	_, err := url.Parse(u)
	return err
}
