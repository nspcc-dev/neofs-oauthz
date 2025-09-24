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
	"go.uber.org/zap/zapcore"
	"golang.org/x/term"
)

const (
	defaultEmailAttr         = "Email"
	defaultBearerCookieName  = "Bearer"
	defaultBearerLifetime    = 30                 // epochs
	defaultMaxObjectSize     = 200 << 20          // 200MB
	defaultMaxObjectLifetime = 4 * 24 * time.Hour // 4 days
	defaultConnectTimeout    = 30 * time.Second
	defaultRebalanceTimer    = 15 * time.Second
	defaultRequestTimeout    = 15 * time.Second

	defaultListenAddress = "0.0.0.0:8083"

	// Logger.
	cfgLoggerLevel    = "logger.level"
	cfgListenAddress  = "listen_address"
	cfgTLSCertificate = "tls_certificate"
	cfgTLSKey         = "tls_key"

	cfgContainerID             = "neofs.cid"
	cfgEmailAttr               = "neofs.bearer_email_attribute"
	cfgUserID                  = "neofs.bearer_user_id"
	cfgBearerLifetime          = "neofs.bearer_lifetime"
	cfgBearerMaxObjectSize     = "neofs.max_object_size"
	cfgBearerMaxObjectLifetime = "neofs.max_object_lifetime"
	cfgNeoFSWalletPath         = "neofs.wallet.path"
	cfgNeoFSWalletPassphrase   = "neofs.wallet.passphrase"
	cfgNeoFSWalletAddress      = "neofs.wallet.address"

	cfgPeers = "peers"

	cfgConTimeout = "connect_timeout"
	cfgReqTimeout = "request_timeout"
	cfgRebalance  = "rebalance_timer"

	// Command line args.
	cmdHelp    = "help"
	cmdVersion = "version"
	cmdConfig  = "config"

	cfgBearerCookieName      = "bearer_cookie_name"
	cfgOauth                 = "oauth"
	cfgOauthIDFmt            = "oauth.%s.id"
	cfgOauthSecretFmt        = "oauth.%s.secret"
	cfgOauthScopesFmt        = "oauth.%s.scopes"
	cfgOauthEndpointAuthFmt  = "oauth.%s.endpoint.auth"
	cfgOauthEndpointTokenFmt = "oauth.%s.endpoint.token"
	cfgRedirectURL           = "redirect.url"
	callbackURLFmt           = "%scallback"

	cfgPrometheusEnabled = "prometheus.enabled"
	cfgPrometheusAddress = "prometheus.address"
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

	if err := v.BindPFlags(flags); err != nil {
		panic(err)
	}

	switch {
	case help != nil && *help:
		fmt.Printf("NeoFS OAuthz %s\n", Version)
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

			k := strings.ReplaceAll(keys[i], ".", "_")
			fmt.Printf("%s_%s = %v\n", Prefix, strings.ToUpper(k), v.Get(keys[i]))
		}

		os.Exit(0)
	case version != nil && *version:
		fmt.Printf("NeoFS OAuthz %s\n", Version)
		os.Exit(0)
	}

	if !v.IsSet(cmdConfig) {
		fmt.Println("config path is mandatory")
		os.Exit(1)
	}
	if err := readConfig(v); err != nil {
		panic(err)
	}

	return v
}

func newLogger(v *viper.Viper) (*zap.Logger, error) {
	var err error
	// default log level is debug
	c := zap.NewDevelopmentConfig()
	if v.IsSet(cfgLoggerLevel) {
		c.Level, err = zap.ParseAtomicLevel(v.GetString(cfgLoggerLevel))
		if err != nil {
			return nil, err
		}
	}

	c.Sampling = nil
	if term.IsTerminal(int(os.Stdout.Fd())) {
		c.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	} else {
		c.EncoderConfig.EncodeTime = func(t time.Time, encoder zapcore.PrimitiveArrayEncoder) {}
	}

	return c.Build()
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
