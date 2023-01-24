package main

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"github.com/nspcc-dev/neo-go/cli/flags"
	"github.com/nspcc-dev/neo-go/cli/input"
	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neo-go/pkg/util"
	"github.com/nspcc-dev/neo-go/pkg/wallet"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/owner"
	"github.com/nspcc-dev/neofs-sdk-go/pool"
	"github.com/nspcc-dev/neofs-send-authz/auth"
	"github.com/nspcc-dev/neofs-send-authz/bearer"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

type (
	app struct {
		log       *zap.Logger
		sdkPool   pool.Pool
		authCfg   *auth.Config
		cfg       *viper.Viper
		webServer *http.Server
		webDone   chan struct{}
	}

	// App is an interface for the main gateway function.
	App interface {
		Wait()
		Serve(context.Context)
	}

	// Option is an application option.
	Option func(a *app)
)

// WithLogger returns Option to set a specific logger.
func WithLogger(l *zap.Logger) Option {
	return func(a *app) {
		if l == nil {
			return
		}
		a.log = l
	}
}

// WithConfig returns Option to use specific Viper configuration.
func WithConfig(c *viper.Viper) Option {
	return func(a *app) {
		if c == nil {
			return
		}
		a.cfg = c
	}
}

func newApp(ctx context.Context, opt ...Option) App {
	var err error
	a := &app{
		log:       zap.L(),
		cfg:       viper.GetViper(),
		webServer: new(http.Server),
		webDone:   make(chan struct{}),
	}

	for i := range opt {
		opt[i](a)
	}

	key, err := a.getKey()
	if err != nil {
		a.log.Fatal("failed to get neofs credentials", zap.Error(err))
	}

	a.initAuthCfg(key)

	pb := new(pool.Builder)
	for i := 0; ; i++ {
		address := a.cfg.GetString(cfgPeers + "." + strconv.Itoa(i) + ".address")
		weight := a.cfg.GetFloat64(cfgPeers + "." + strconv.Itoa(i) + ".weight")
		priority := a.cfg.GetInt(cfgPeers + "." + strconv.Itoa(i) + ".priority")
		if address == "" {
			break
		}
		if weight <= 0 { // unspecified or wrong
			weight = 1
		}
		if priority <= 0 { // unspecified or wrong
			priority = 1
		}
		pb.AddNode(address, priority, weight)
		a.log.Info("add connection", zap.String("address", address), zap.Float64("weight", weight), zap.Int("priority", priority))
	}

	opts := &pool.BuilderOptions{
		Key:                     &key.PrivateKey,
		NodeConnectionTimeout:   a.cfg.GetDuration(cfgConTimeout),
		NodeRequestTimeout:      a.cfg.GetDuration(cfgReqTimeout),
		ClientRebalanceInterval: a.cfg.GetDuration(cfgRebalance),
	}

	a.sdkPool, err = pb.Build(ctx, opts)
	if err != nil {
		a.log.Fatal("failed to create connection pool", zap.Error(err))
	}

	return a
}

func (a *app) getKey() (*keys.PrivateKey, error) {
	walletPath := a.cfg.GetString(cfgNeoFSWalletPath)
	if len(walletPath) == 0 {
		return nil, fmt.Errorf("wallet path can't be empty")
	}

	wlt, err := wallet.NewWalletFromFile(walletPath)
	if err != nil {
		return nil, err
	}

	var addr util.Uint160
	addrStr := a.cfg.GetString(cfgNeoFSWalletAddress)
	if len(addrStr) == 0 {
		addr = wlt.GetChangeAddress()
	} else {
		addr, err = flags.ParseAddress(addrStr)
		if err != nil {
			return nil, err
		}
	}

	account := wlt.GetAccount(addr)
	if account == nil {
		return nil, fmt.Errorf("couldn't find wallet account: %s", addrStr)
	}

	var password string
	if a.cfg.IsSet(cfgNeoFSWalletPassphrase) {
		password = a.cfg.GetString(cfgNeoFSWalletPassphrase)
	} else {
		pwd, err := input.ReadPassword(fmt.Sprintf("Enter password for %s > ", walletPath))
		if err != nil {
			return nil, fmt.Errorf("couldn't read password")
		}
		password = pwd
	}

	if err = account.Decrypt(password, wlt.Scrypt); err != nil {
		return nil, err
	}

	return account.PrivateKey(), nil
}

func (a *app) initAuthCfg(key *keys.PrivateKey) {
	var err error
	containerID := cid.New()
	containerStr := a.cfg.GetString(cfgContainerID)
	if len(containerStr) == 0 {
		err = fmt.Errorf("no container id specified")
	} else {
		err = containerID.Parse(containerStr)
	}
	if err != nil {
		a.log.Fatal("failed to get container id", zap.Error(err))
	}

	ownerID := new(owner.ID)
	ownerStr := a.cfg.GetString(cfgOwnerID)
	if len(ownerStr) == 0 {
		err = fmt.Errorf("no owner id specified")
	} else {
		err = ownerID.Parse(ownerStr)
	}
	if err != nil {
		a.log.Fatal("failed to get owner id", zap.Error(err))
	}

	a.authCfg = &auth.Config{
		Bearer: &bearer.Config{
			Key:         key,
			OwnerID:     ownerID,
			ContainerID: containerID,
			LifeTime:    a.cfg.GetUint64(cfgBearerLifetime),
		},
		Oauth:         make(map[string]*auth.ServiceOauth),
		TLSEnabled:    a.cfg.GetString(cfgTLSCertificate) != "" || a.cfg.GetString(cfgTLSKey) != "",
		Host:          a.cfg.GetString(cfgListenAddress),
		RedirectURL:   a.cfg.GetString(cfgRedirectURL),
		RedirectOauth: a.cfg.GetString(cfgRedirectOauth),
	}

	scheme := "http"
	if a.authCfg.TLSEnabled {
		scheme += "s"
	}
	base := a.authCfg.Host
	if len(a.authCfg.RedirectOauth) != 0 {
		base = a.authCfg.RedirectOauth
	}
	redirectURL := fmt.Sprintf(callbackURLFmt, scheme, base)

	for key := range a.cfg.GetStringMap(cfgOauth) {
		oauth := &oauth2.Config{
			RedirectURL:  redirectURL,
			ClientID:     a.cfg.GetString(fmt.Sprintf(cfgOauthIDFmt, key)),
			ClientSecret: a.cfg.GetString(fmt.Sprintf(cfgOauthSecretFmt, key)),
			Scopes:       a.cfg.GetStringSlice(fmt.Sprintf(cfgOauthScopesFmt, key)),
			Endpoint: oauth2.Endpoint{
				AuthURL:  a.cfg.GetString(fmt.Sprintf(cfgOauthEndpointAuthFmt, key)),
				TokenURL: a.cfg.GetString(fmt.Sprintf(cfgOauthEndpointTokenFmt, key)),
			},
		}

		if serviceConfig, err := auth.NewServiceConfig(key, oauth); err != nil {
			a.log.Fatal("failed to init services", zap.Error(err))
		} else {
			a.authCfg.Oauth[key] = serviceConfig
		}
	}
}

func (a *app) Wait() {
	a.log.Info("starting application")
	<-a.webDone // wait for web-server to be stopped
}

func (a *app) Serve(ctx context.Context) {
	go func() {
		<-ctx.Done()
		a.log.Info("shutting down server", zap.Error(a.webServer.Shutdown(ctx)))
		close(a.webDone)
	}()

	authenticator, err := auth.New(a.log, a.sdkPool, a.authCfg)
	if err != nil {
		a.log.Fatal("could not init authenticator", zap.Error(err))
	}

	myHandler := http.DefaultServeMux
	myHandler.HandleFunc("/", authenticator.Index)
	myHandler.HandleFunc("/login", authenticator.LogInWith)
	myHandler.HandleFunc("/callback", authenticator.Callback)
	a.webServer.Handler = myHandler

	a.webServer.Addr = a.authCfg.Host
	if a.authCfg.TLSEnabled {
		a.log.Info("running web server (TLS-enabled)", zap.String("address", a.webServer.Addr))
		err = a.webServer.ListenAndServeTLS(a.cfg.GetString(cfgTLSCertificate), a.cfg.GetString(cfgTLSKey))
	} else {
		a.log.Info("running web server", zap.String("address", a.webServer.Addr))
		err = a.webServer.ListenAndServe()
	}
	if err != nil {
		a.log.Fatal("could not start server", zap.Error(err))
	}
}
