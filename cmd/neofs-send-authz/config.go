package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

const (
	defaultRebalanceTimer = 15 * time.Second
	defaultRequestTimeout = 15 * time.Second
	defaultConnectTimeout = 30 * time.Second
	defaultBearerLifetime = 30

	defaultListenAddress = "0.0.0.0:8083"

	// Logger.
	cfgLoggerLevel = "logger.level"
	cfgLoggerFormat             = "logger.format"
	cfgLoggerTraceLevel         = "logger.trace_level"
	cfgLoggerNoCaller           = "logger.no_caller"
	cfgLoggerNoDisclaimer       = "logger.no_disclaimer"
	cfgLoggerSamplingInitial    = "logger.sampling.initial"
	cfgLoggerSamplingThereafter = "logger.sampling.thereafter"

	cfgListenAddress  = "listen_address"
	cfgTLSCertificate = "tls_certificate"
	cfgTLSKey         = "tls_key"

	cfgContainerID           = "neofs.cid"
	cfgOwnerID               = "neofs.owner_id"
	cfgBearerLifetime        = "neofs.bearer_lifetime"
	cfgNeoFSWalletPath       = "neofs.wallet.path"
	cfgNeoFSWalletPassphrase = "neofs.wallet.passphrase"
	cfgNeoFSWalletAddress    = "neofs.wallet.address"

	cfgPeers = "peers"

	cfgConTimeout = "connect_timeout"
	cfgReqTimeout = "request_timeout"
	cfgRebalance  = "rebalance_timer"

	// Command line args.
	cmdHelp    = "help"
	cmdVersion = "version"
	cmdConfig  = "config"
)

const (
	cfgOauth                 = "oauth"
	cfgOauthIDFmt            = "oauth.%s.id"
	cfgOauthSecretFmt        = "oauth.%s.secret"
	cfgOauthScopesFmt        = "oauth.%s.scopes"
	cfgOauthEndpointAuthFmt  = "oauth.%s.endpoint.auth"
	cfgOauthEndpointTokenFmt = "oauth.%s.endpoint.token"
	cfgRedirectURL           = "redirect.url"
	callbackURLFmt           = "%scallback"
)

var ignore = map[string]struct{}{
	cmdHelp:    {},
	cmdVersion: {},
}

func newConfig() *viper.Viper {
	v := viper.New()

	v.AutomaticEnv()
	v.SetEnvPrefix(Prefix)
	v.SetConfigType("yaml")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AllowEmptyEnv(true)

	flags := pflag.NewFlagSet("flagSet", pflag.ExitOnError)
	flags.SetOutput(os.Stdout)
	flags.SortFlags = false

	// set cmd flags
	help := flags.BoolP(cmdHelp, "h", false, "show help")
	version := flags.BoolP(cmdVersion, "v", false, "show version")
	flags.StringP(cmdConfig, "c", "", "set config path")

	if err := flags.Parse(os.Args); err != nil {
		panic(err)
	}

	// logger:
	v.SetDefault(cfgLoggerLevel, "debug")
	v.SetDefault(cfgLoggerFormat, "console")
	v.SetDefault(cfgLoggerTraceLevel, "panic")
	v.SetDefault(cfgLoggerNoCaller, false)
	v.SetDefault(cfgLoggerNoDisclaimer, true)
	v.SetDefault(cfgLoggerSamplingInitial, 1000)
	v.SetDefault(cfgLoggerSamplingThereafter, 1000)

	if err := v.BindPFlags(flags); err != nil {
		panic(err)
	}

	switch {
	case help != nil && *help:
		fmt.Printf("NeoFS Send Authz %s\n", Version)
		flags.PrintDefaults()

		fmt.Println()
		fmt.Println("Default environments:")
		fmt.Println()
		keys := v.AllKeys()
		sort.Strings(keys)

		for i := range keys {
			if _, ok := ignore[keys[i]]; ok {
				continue
			}

			k := strings.Replace(keys[i], ".", "_", -1)
			fmt.Printf("%s_%s = %v\n", Prefix, strings.ToUpper(k), v.Get(keys[i]))
		}

		os.Exit(0)
	case version != nil && *version:
		fmt.Printf("NeoFS Send Authz %s\n", Version)
		os.Exit(0)
	}

	if !v.IsSet(cmdConfig) {
		fmt.Println("config path is mandatory")
		os.Exit(1)
	} else {
		if err := readConfig(v); err != nil {
			panic(err)
		}
	}

	return v
}

func readConfig(v *viper.Viper) error {
	cfgFileName := v.GetString(cmdConfig)
	cfgFile, err := os.Open(cfgFileName)
	if err != nil {
		return err
	}
	if err = v.ReadConfig(cfgFile); err != nil {
		return err
	}

	return cfgFile.Close()
}
