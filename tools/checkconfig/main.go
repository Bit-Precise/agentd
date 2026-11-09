// Command checkconfig validates the agentd configuration files embedded in
// Kubernetes manifests (ConfigMaps with a config.yaml key), e.g.:
//
//	helm template x deploy/helm/agentd | go run ./tools/checkconfig
package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"

	"agentd/internal/control"
	"agentd/internal/relay"
)

func main() {
	dec := yaml.NewDecoder(os.Stdin)
	n, bad := 0, 0
	for {
		var doc struct {
			Kind     string                `yaml:"kind"`
			Metadata struct{ Name string } `yaml:"metadata"`
			Data     map[string]string     `yaml:"data"`
		}
		if err := dec.Decode(&doc); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			fmt.Fprintln(os.Stderr, "decode:", err)
			os.Exit(1)
		}
		cfg, ok := doc.Data["config.yaml"]
		if doc.Kind != "ConfigMap" || !ok {
			continue
		}
		var head struct{ Kind string }
		_ = yaml.NewDecoder(bytes.NewReader([]byte(cfg))).Decode(&head)
		var err error
		switch head.Kind {
		case "AgentserverConfiguration":
			_, err = control.ParseServerConfig([]byte(cfg))
		case "AgentrelayConfiguration":
			_, err = relay.ParseConfig([]byte(cfg))
		default:
			continue
		}
		n++
		if err != nil {
			bad++
			fmt.Printf("%s (%s): %v\n", doc.Metadata.Name, head.Kind, err)
		} else {
			fmt.Printf("%s (%s): ok\n", doc.Metadata.Name, head.Kind)
		}
	}
	if n == 0 || bad > 0 {
		os.Exit(1)
	}
}
