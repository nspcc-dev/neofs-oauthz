package main

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

const (
	namespace = "neofs_oauthz"
)

type (
	// gateMetrics is a metrics collection.
	gateMetrics struct {
		stateMetrics
	}

	stateMetrics struct {
		up        prometheus.Gauge
		gwVersion *prometheus.GaugeVec
	}
)

// newGateMetrics creates new metrics for the app.
func newGateMetrics() *gateMetrics {
	stateMetric := newStateMetrics()
	stateMetric.register()

	return &gateMetrics{
		stateMetrics: *stateMetric,
	}
}

func newStateMetrics() *stateMetrics {
	return &stateMetrics{
		up: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "up",
			Help:      "App is up and running",
		}),
		gwVersion: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Help:      "App version",
				Name:      "version",
				Namespace: namespace,
			},
			[]string{"version"},
		),
	}
}

func (m stateMetrics) register() {
	prometheus.MustRegister(m.up)
	prometheus.MustRegister(m.gwVersion)
}

// SetServiceStarted updates the `up` metric with the value 1.
func (m stateMetrics) SetServiceStarted() {
	m.up.Set(1.0)
}

// newPrometheus creates a new service for gathering prometheus metrics.
func newPrometheus(log *zap.Logger, enabled bool, address string) *service {
	return newService(
		&http.Server{
			Addr:    address,
			Handler: promhttp.Handler(),
		},
		enabled,
		log.With(zap.String("service", "Prometheus")),
	)
}

// SetAppVersion increments the app version metric counter for the specified version label.
func (g *gateMetrics) SetAppVersion(ver string) {
	g.gwVersion.WithLabelValues(ver).Add(1)
}
