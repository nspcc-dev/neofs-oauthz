package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/nspcc-dev/neo-go/cli/flags"
	"github.com/nspcc-dev/neo-go/cli/input"
	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neo-go/pkg/util"
	"github.com/nspcc-dev/neo-go/pkg/wallet"
	"github.com/nspcc-dev/neofs-oauthz/auth"
	"github.com/nspcc-dev/neofs-oauthz/bearer"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/pool"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

type (
	app struct {
		log       *zap.Logger
		sdkPool   *pool.Pool
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
	a.initPool(ctx, key)

	return a
}

func (a *app) initPool(ctx context.Context, key *keys.PrivateKey) {
	var (
		err error
		p   pool.InitParameters
	)
	p.SetSigner(user.NewAutoIDSignerRFC6979(key.PrivateKey))

	connTimeout := a.cfg.GetDuration(cfgConTimeout)
	if connTimeout <= 0 {
		connTimeout = defaultConnectTimeout
	}
	p.SetNodeDialTimeout(connTimeout)

	healthCheckTimeout := a.cfg.GetDuration(cfgReqTimeout)
	if healthCheckTimeout <= 0 {
		healthCheckTimeout = defaultRequestTimeout
	}
	p.SetHealthcheckTimeout(healthCheckTimeout)

	rebalanceInterval := a.cfg.GetDuration(cfgRebalance)
	if rebalanceInterval <= 0 {
		rebalanceInterval = defaultRebalanceTimer
	}
	p.SetClientRebalanceInterval(rebalanceInterval)

	for i := 0; ; i++ {
		key := cfgPeers + "." + strconv.Itoa(i)
		if !a.cfg.IsSet(key) {
			break
		}
		key += "."
		address := a.cfg.GetString(key + "address")
		weight := a.cfg.GetFloat64(key + "weight")
		priority := a.cfg.GetInt(key + "priority")
		if address == "" {
			a.log.Fatal("node address is empty or malformed")
		}
		if weight <= 0 { // unspecified or wrong
			weight = 1
		}
		if priority <= 0 { // unspecified or wrong
			priority = 1
		}
		p.AddNode(pool.NewNodeParam(priority, address, weight))
		a.log.Info("add connection", zap.String("address", address), zap.Float64("weight", weight), zap.Int("priority", priority))
	}

	a.sdkPool, err = pool.NewPool(p)
	if err != nil {
		a.log.Fatal("failed to create connection pool", zap.Error(err))
	}

	if err = a.sdkPool.Dial(ctx); err != nil {
		a.log.Fatal("failed to dial connection pool", zap.Error(err))
	}
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
	var containerID cid.ID
	if err := containerID.DecodeString(a.cfg.GetString(cfgContainerID)); err != nil {
		a.log.Fatal("container id is empty or malformed", zap.Error(err))
	}

	var (
		cfgUser = a.cfg.GetString(cfgUserID)
		userID  *user.ID
	)
	if cfgUser != "" {
		userID = new(user.ID)
		if err := userID.DecodeString(cfgUser); err != nil {
			a.log.Fatal("user id is malformed", zap.Error(err))
		}
	}

	emailattr := a.cfg.GetString(cfgEmailAttr)
	if len(emailattr) == 0 {
		emailattr = defaultEmailAttr
	}
	lifetime := a.cfg.GetUint64(cfgBearerLifetime)
	if lifetime == 0 {
		lifetime = defaultBearerLifetime
	}
	maxObjectSize := a.cfg.GetUint64(cfgBearerMaxObjectSize)
	if maxObjectSize == 0 {
		maxObjectSize = defaultMaxObjectSize
	}
	objectMaxLifetime := a.cfg.GetDuration(cfgBearerMaxObjectLifetime)
	if objectMaxLifetime == 0 {
		objectMaxLifetime = defaultMaxObjectLifetime
	}

	listenAddress := a.cfg.GetString(cfgListenAddress)
	if len(listenAddress) == 0 {
		listenAddress = defaultListenAddress
	}
	bearerCookieName := a.cfg.GetString(cfgBearerCookieName)
	if len(bearerCookieName) == 0 {
		bearerCookieName = defaultBearerCookieName
	}

	a.authCfg = &auth.Config{
		Bearer: &bearer.Config{
			EmailAttr:         emailattr,
			Key:               key,
			UserID:            userID,
			ContainerID:       containerID,
			LifeTime:          lifetime,
			MaxObjectSize:     maxObjectSize,
			ObjectMaxLifetime: objectMaxLifetime,
		},
		BearerCookieName: bearerCookieName,
		Oauth:            make(map[string]*auth.ServiceOauth),
		TLSEnabled:       a.cfg.GetString(cfgTLSCertificate) != "" || a.cfg.GetString(cfgTLSKey) != "",
		Host:             listenAddress,
		RedirectURL:      a.cfg.GetString(cfgRedirectURL),
	}

	redirectURLCallback := fmt.Sprintf(callbackURLFmt, a.authCfg.RedirectURL)

	for key := range a.cfg.GetStringMap(cfgOauth) {
		oauth := &oauth2.Config{
			RedirectURL:  redirectURLCallback,
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
	if !errors.Is(err, http.ErrServerClosed) {
		a.log.Fatal("could not start server", zap.Error(err))
	}
}
