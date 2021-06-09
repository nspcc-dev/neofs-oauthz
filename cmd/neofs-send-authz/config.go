package main

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	defaultRebalanceTimer = 15 * time.Second
	defaultRequestTimeout = 15 * time.Second
	defaultConnectTimeout = 30 * time.Second

	defaultKeepaliveTime    = 10 * time.Second
	defaultKeepaliveTimeout = 10 * time.Second

	// Logger.
	cfgLoggerLevel              = "logger.level"
	cfgLoggerFormat             = "logger.format"
	cfgLoggerTraceLevel         = "logger.trace_level"
	cfgLoggerNoCaller           = "logger.no_caller"
	cfgLoggerNoDisclaimer       = "logger.no_disclaimer"
	cfgLoggerSamplingInitial    = "logger.sampling.initial"
	cfgLoggerSamplingThereafter = "logger.sampling.thereafter"

	cfgListenAddress  = "listen_address"
	cfgTLSCertificate = "tls_certificate"
	cfgTLSKey         = "tls_key"
	cfgContainerID    = "cid"
	cfgGateway        = "gateway"
	cfgOwnerID        = "owner_id"
	cfgBearerLifetime = "bearer_lifetime"

	cfgPeers = "peers"

	// KeepAlive.
	cfgKeepaliveTime                = "keepalive.time"
	cfgKeepaliveTimeout             = "keepalive.timeout"
	cfgKeepalivePermitWithoutStream = "keepalive.permit_without_stream"

	cfgConTimeout = "connect_timeout"
	cfgReqTimeout = "request_timeout"
	cfgRebalance  = "rebalance_timer"

	// Application.
	cfgApplicationName    = "app.name"
	cfgApplicationVersion = "app.version"

	// Command line args.
	cmdHelp     = "help"
	cmdVersion  = "version"
	cmdNeoFSKey = "key"
)

const (
	cfgOauth                 = "oauth"
	cfgOauthIDFmt            = "oauth.%s.id"
	cfgOauthSecretFmt        = "oauth.%s.secret"
	cfgOauthScopesFmt        = "oauth.%s.scopes"
	cfgOauthEndpointAuthFmt  = "oauth.%s.endpoint.auth"
	cfgOauthEndpointTokenFmt = "oauth.%s.endpoint.token"
	callbackURLFmt           = "%s://%s/callback"
)

var ignore = map[string]struct{}{
	cfgApplicationName:    {},
	cfgApplicationVersion: {},
	cfgPeers:              {},
	cmdHelp:               {},
	cmdVersion:            {},
}

func newConfig() *viper.Viper {
	v := viper.New()

	v.AutomaticEnv()
	v.SetEnvPrefix(Prefix)
	v.SetConfigType("yaml")
	v.AddConfigPath("./")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// flags setup:
	flags := pflag.NewFlagSet("commandline", pflag.ExitOnError)
	flags.SetOutput(os.Stdout)
	flags.SortFlags = false

	help := flags.BoolP(cmdHelp, "h", false, "show help")
	version := flags.BoolP(cmdVersion, "v", false, "show version")

	flags.StringP(cmdNeoFSKey, "k", "", `path to private key file, hex string or wif `)
	flags.String(cfgContainerID, "", `container id`)
	flags.String(cfgOwnerID, "", `token owner`)

	// set prefers:
	v.Set(cfgApplicationName, "neofs-send-authz")
	v.Set(cfgApplicationVersion, Version)

	// set defaults:
	flags.Duration(cfgConTimeout, defaultConnectTimeout, "gRPC connect timeout")
	flags.Duration(cfgReqTimeout, defaultRequestTimeout, "gRPC request timeout")
	flags.Duration(cfgRebalance, defaultRebalanceTimer, "gRPC connection rebalance timer")
	flags.String(cfgListenAddress, "0.0.0.0:8083", "address to listen")
	flags.String(cfgGateway, "localhost:8082", `gateway url`)
	flags.String(cfgTLSCertificate, "", "TLS certificate path")
	flags.String(cfgTLSKey, "", "TLS key path")
	flags.Uint64(cfgBearerLifetime, 30, "bearer lifetime in epoch")

	peers := flags.StringArrayP(cfgPeers, "p", nil, "NeoFS nodes")

	// logger:
	v.SetDefault(cfgLoggerLevel, "debug")
	v.SetDefault(cfgLoggerFormat, "console")
	v.SetDefault(cfgLoggerTraceLevel, "panic")
	v.SetDefault(cfgLoggerNoCaller, false)
	v.SetDefault(cfgLoggerNoDisclaimer, true)
	v.SetDefault(cfgLoggerSamplingInitial, 1000)
	v.SetDefault(cfgLoggerSamplingThereafter, 1000)

	v.SetDefault(cfgKeepaliveTime, defaultKeepaliveTime)
	v.SetDefault(cfgKeepaliveTimeout, defaultKeepaliveTimeout)
	v.SetDefault(cfgKeepalivePermitWithoutStream, true)

	if err := v.BindPFlags(flags); err != nil {
		panic(err)
	}

	if err := v.ReadInConfig(); err != nil {
		panic(err)
	}

	if err := flags.Parse(os.Args); err != nil {
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

	if peers != nil && len(*peers) > 0 {
		for i := range *peers {
			v.SetDefault(cfgPeers+"."+strconv.Itoa(i)+".address", (*peers)[i])
			v.SetDefault(cfgPeers+"."+strconv.Itoa(i)+".weight", 1)
		}
	}

	return v
}
