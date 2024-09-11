package main

import (
	"context"
	"errors"
	"net/http"
	"time"

	"go.uber.org/zap"
)

const defaultShutdownTimeout = 15 * time.Second

type (
	// service serves metrics.
	service struct {
		*http.Server
		enabled bool
		log     *zap.Logger
	}

	// services is a collection for services which can be started in background.
	services struct {
		services []*service
	}
)

// newService is a constructor for service.
func newService(
	server *http.Server,
	enabled bool,
	log *zap.Logger,
) *service {
	return &service{
		Server:  server,
		enabled: enabled,
		log:     log,
	}
}

// Start runs http service with the exposed endpoint on the configured port.
func (ms *service) Start() {
	if !ms.enabled {
		ms.log.Info("service hasn't started since it's disabled")
	}

	ms.log.Info("service is running", zap.String("endpoint", ms.Addr))

	if err := ms.ListenAndServe(); err != nil {
		if !errors.Is(err, http.ErrServerClosed) {
			ms.log.Warn("service couldn't start on configured port", zap.Error(err))
		}
	}
}

// ShutDown stops the service.
func (ms *service) ShutDown(ctx context.Context) {
	ms.log.Info("shutting down service", zap.String("endpoint", ms.Addr))

	if err := ms.Shutdown(ctx); err != nil {
		ms.log.Panic("can't shut down service", zap.Error(err))
	}
}

// newServices is a constructor for services.
func newServices(servioceList []*service) *services {
	return &services{
		services: servioceList,
	}
}

// RunServices function runs all services.
func (x *services) RunServices() {
	for _, s := range x.services {
		go s.Start()
	}
}

// StopServices function is shutting down all services.
func (x *services) StopServices() {
	ctx, cancel := shutdownContext()
	defer cancel()

	for _, s := range x.services {
		go s.ShutDown(ctx)
	}
}

func shutdownContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), defaultShutdownTimeout)
}
