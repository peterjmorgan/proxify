package certs

// Temporary Martian bridge: keeps the old serving path building while core
// mitm.go no longer imports Martian. Removed when Martian serving is retired.

import (
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/martian/v3/mitm"
)

// GetMitMConfig returns mitm config for martian
func GetMitMConfig() *mitm.Config {
	cfg, err := mitm.NewConfig(cert, pkey)
	if err != nil {
		gologger.Fatal().Msgf("failed to create mitm config")
	}
	return cfg
}
