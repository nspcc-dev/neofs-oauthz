package main

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"strconv"

	"github.com/nspcc-dev/neofs-api-go/pkg/container"
	"github.com/nspcc-dev/neofs-api-go/pkg/owner"
	"github.com/nspcc-dev/neofs-sdk-go/pkg/neofs"
	"github.com/nspcc-dev/neofs-sdk-go/pkg/pool"
	"github.com/nspcc-dev/neofs-send-authz/auth"
	"github.com/nspcc-dev/neofs-send-authz/bearer"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

type (
	app struct {
		log       *zap.Logger
		plant     neofs.ClientPlant
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

	var creds neofs.Credentials
	keystring := a.cfg.GetString(cmdNeoFSKey)
	if len(keystring) == 0 {
		err = fmt.Errorf("no key specified")
	} else {
		creds, err = neofs.NewCredentials(keystring)
	}
	if err != nil {
		a.log.Fatal("failed to get neofs credentials", zap.Error(err))
	}

	a.initAuthCfg(creds)

	pb := new(pool.Builder)
	for i := 0; ; i++ {
		address := a.cfg.GetString(cfgPeers + "." + strconv.Itoa(i) + ".address")
		weight := a.cfg.GetFloat64(cfgPeers + "." + strconv.Itoa(i) + ".weight")
		if address == "" {
			break
		}
		if weight <= 0 { // unspecified or wrong
			weight = 1
		}
		pb.AddNode(address, weight)
		a.log.Info("add connection", zap.String("address", address), zap.Float64("weight", weight))
	}

	opts := &pool.BuilderOptions{
		Key:                     creds.PrivateKey(),
		NodeConnectionTimeout:   a.cfg.GetDuration(cfgConTimeout),
		NodeRequestTimeout:      a.cfg.GetDuration(cfgReqTimeout),
		ClientRebalanceInterval: a.cfg.GetDuration(cfgRebalance),
		SessionExpirationEpoch:  math.MaxUint64,
		KeepaliveTime:           a.cfg.GetDuration(cfgKeepaliveTime),
		KeepaliveTimeout:        a.cfg.GetDuration(cfgKeepaliveTimeout),
		KeepalivePermitWoStream: a.cfg.GetBool(cfgKeepalivePermitWithoutStream),
	}
	_ = opts
	pool, err := pb.Build(ctx, opts)
	if err != nil {
		a.log.Fatal("failed to create connection pool", zap.Error(err))
	}
	a.plant, err = neofs.NewClientPlant(ctx, pool, creds)
	if err != nil {
		a.log.Fatal("failed to create neofs client plant")
	}

	return a
}

func (a *app) initAuthCfg(creds neofs.Credentials) {
	var err error
	containerID := new(container.ID)
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
			Creds:       creds,
			OwnerID:     ownerID,
			ContainerID: containerID,
			LifeTime:    a.cfg.GetUint64(cfgBearerLifetime),
		},
		Oauth:       make(map[string]*auth.ServiceOauth),
		TLSEnabled:  a.cfg.GetString(cfgTLSCertificate) != "" || a.cfg.GetString(cfgTLSKey) != "",
		Host:        a.cfg.GetString(cfgListenAddress),
		Gateway:     a.cfg.GetString(cfgGateway),
		ContainerID: containerStr,
		RedirectURL: a.cfg.GetString(cfgRedirectURL),
	}

	scheme := "http"
	if a.authCfg.TLSEnabled {
		scheme += "s"
	}
	redirectURL := fmt.Sprintf(callbackURLFmt, scheme, a.authCfg.Host)

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

	authenticator, err := auth.New(a.log, a.plant, a.authCfg)
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
