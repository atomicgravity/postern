package cliapp

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

const (
	configureBrokerFlag           = "broker"
	configureIDPIssuerFlag        = "idp-issuer"
	configureIDPClientIDFlag      = "idp-client-id"
	configureIDPAudienceFlag      = "idp-audience"
	configureIDPAudienceParamFlag = "idp-audience-param"
	configureIDPScopesFlag        = "idp-scopes"
	configureReplaceFlag          = "replace"
)

type configureOptions struct {
	Broker           string
	IDPIssuer        string
	IDPClientID      string
	IDPAudience      string
	IDPAudienceParam string
	IDPScopes        string
	Replace          bool
}

func configureCommand(rt runtime) *cobra.Command {
	options := configureOptions{}
	command := &cobra.Command{
		Use:   "configure",
		Short: "Write or update CLI profile configuration",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConfigure(cmd, rt, options)
		},
	}

	flags := command.Flags()
	flags.StringVar(&options.Broker, configureBrokerFlag, "", "broker URL")
	flags.StringVar(&options.IDPIssuer, configureIDPIssuerFlag, "", "IdP issuer URL")
	flags.StringVar(&options.IDPClientID, configureIDPClientIDFlag, "", "IdP client ID")
	flags.StringVar(&options.IDPAudience, configureIDPAudienceFlag, "", "IdP audience")
	flags.StringVar(&options.IDPAudienceParam, configureIDPAudienceParamFlag, "", "OAuth audience parameter name")
	flags.StringVar(&options.IDPScopes, configureIDPScopesFlag, "", "extra OAuth scopes")
	flags.BoolVar(&options.Replace, configureReplaceFlag, false, "replace the selected profile instead of merging")

	return command
}

func runConfigure(command *cobra.Command, rt runtime, options configureOptions) error {
	configPath, err := resolveConfigPath(rt.binaryName, rt.configPath)
	if err != nil {
		return err
	}

	config, err := loadConfigFileForConfigure(configPath)
	if err != nil {
		return fmt.Errorf("load config %q: %w", configPath, err)
	}

	if config.Profiles == nil {
		config.Profiles = map[string]Profile{}
	}

	profileName := commandProfileName(command, rt.lookupEnv)
	profile := Profile{}
	if !options.Replace {
		profile = config.Profiles[profileName]
	}

	profile = trimProfile(applyConfigureFlags(profile, command, options))

	// Validate before defaulting so the persisted YAML preserves the
	// engineer's audience-param omission — defaults fill at resolve time.
	if err := profile.Validate(); err != nil {
		return fmt.Errorf("profile %q: %w", profileName, err)
	}

	config.Profiles[profileName] = profile
	if err := SaveConfigFile(configPath, config); err != nil {
		return fmt.Errorf("save config %q: %w", configPath, err)
	}

	_, err = fmt.Fprintf(command.OutOrStdout(), "Configured profile %q at %s\n", profileName, configPath)
	return err
}

func loadConfigFileForConfigure(path string) (Config, error) {
	config, err := LoadConfigFile(path)
	if err == nil {
		return config, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return Config{Profiles: map[string]Profile{}}, nil
	}
	return Config{}, err
}

func applyConfigureFlags(profile Profile, command *cobra.Command, options configureOptions) Profile {
	flags := command.Flags()
	if flags.Changed(configureBrokerFlag) {
		profile.Broker = options.Broker
	}
	if flags.Changed(configureIDPIssuerFlag) {
		profile.IDP.Issuer = options.IDPIssuer
	}
	if flags.Changed(configureIDPClientIDFlag) {
		profile.IDP.ClientID = options.IDPClientID
	}
	if flags.Changed(configureIDPAudienceFlag) {
		profile.IDP.Audience = options.IDPAudience
	}
	if flags.Changed(configureIDPAudienceParamFlag) {
		profile.IDP.AudienceParam = options.IDPAudienceParam
	}
	if flags.Changed(configureIDPScopesFlag) {
		profile.IDP.Scopes = options.IDPScopes
	}
	return profile
}
