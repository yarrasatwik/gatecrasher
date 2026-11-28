package main

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// envConfig is the YAML shape written for `ci --from-env`. It is marshaled
// with a real YAML encoder, so no input value can break out of its scalar.
type envConfig struct {
	AllowedDomains []string     `yaml:"allowed_domains"`
	Flagsmith      envFlagsmith `yaml:"flagsmith"`
	AppRepo        string       `yaml:"app_repo"`
	StateDir       string       `yaml:"state_dir"`
}

type envFlagsmith struct {
	APIURL          string   `yaml:"api_url"`
	AllowedAPIHosts []string `yaml:"allowed_api_hosts"`
	Project         string   `yaml:"project"`
	Environments    []string `yaml:"environments"`
	UseCLI          bool     `yaml:"use_cli"`
}

// ciInputs are the action inputs, read from GC_* environment variables.
type ciInputs struct {
	APIURL, ServerKey, Project, Environment, AppPath, FailOn string
}

func ciInputsFromEnv(get func(string) string) ciInputs {
	in := ciInputs{
		APIURL:      get("GC_API_URL"),
		ServerKey:   get("GC_SERVER_KEY"),
		Project:     get("GC_PROJECT"),
		Environment: get("GC_ENV"),
		AppPath:     get("GC_APP"),
		FailOn:      get("GC_FAIL_ON"),
	}
	if in.Environment == "" {
		in.Environment = "Production"
	}
	if in.AppPath == "" {
		in.AppPath = "."
	}
	if in.FailOn == "" {
		in.FailOn = "high"
	}
	return in
}

// buildCIConfig renders the gatecrasher.yaml for the Action from its inputs.
func buildCIConfig(in ciInputs, stateDir string) ([]byte, error) {
	if in.APIURL == "" {
		return nil, errors.New("GC_API_URL is required")
	}
	if in.Project == "" {
		return nil, errors.New("GC_PROJECT is required")
	}
	u, err := url.Parse(in.APIURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("GC_API_URL %q is not a valid URL", in.APIURL)
	}
	cfg := envConfig{
		AllowedDomains: []string{},
		Flagsmith: envFlagsmith{
			APIURL:          in.APIURL,
			AllowedAPIHosts: []string{u.Host},
			Project:         in.Project,
			Environments:    []string{in.Environment},
		},
		AppRepo:  in.AppPath,
		StateDir: stateDir,
	}
	return yaml.Marshal(cfg)
}

// writeCIConfigFromEnv builds the config from GC_* variables, writes it to
// the runner temp dir and returns its path with the inputs. The server key
// is handed to the config loader through its normal environment variable.
func writeCIConfigFromEnv() (string, ciInputs, error) {
	in := ciInputsFromEnv(os.Getenv)
	tmp := os.Getenv("RUNNER_TEMP")
	if tmp == "" {
		tmp = os.TempDir()
	}
	data, err := buildCIConfig(in, filepath.Join(tmp, "gatecrasher-state"))
	if err != nil {
		return "", in, err
	}
	if in.ServerKey != "" {
		if strings.ContainsAny(in.Environment, ",=") {
			return "", in, errors.New("GC_ENV must not contain ',' or '=' when a server key is set")
		}
		if err := os.Setenv("GATECRASHER_SERVER_KEYS", in.Environment+"="+in.ServerKey); err != nil {
			return "", in, err
		}
	}
	path := filepath.Join(tmp, "gatecrasher.yaml")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return "", in, err
	}
	return path, in, nil
}
