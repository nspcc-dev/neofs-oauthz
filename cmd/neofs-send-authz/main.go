package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	config := newConfig()
	l, err := newLogger(config)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	globalContext, _ := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	app := newApp(globalContext, WithLogger(l), WithConfig(config))
	go app.Serve(globalContext)
	app.Wait()
}

func newLogger(v *viper.Viper) *zap.Logger {
	options := []logger.Option{
		logger.WithLevel(v.GetString(cfgLoggerLevel)),
		logger.WithTraceLevel(v.GetString(cfgLoggerTraceLevel)),
		logger.WithFormat(v.GetString(cfgLoggerFormat)),
		logger.WithSamplingInitial(v.GetInt(cfgLoggerSamplingInitial)),
		logger.WithSamplingThereafter(v.GetInt(cfgLoggerSamplingThereafter)),
		logger.WithAppName(v.GetString(cfgApplicationName)),
		logger.WithAppVersion(v.GetString(cfgApplicationVersion)),
	}
	if v.GetBool(cfgLoggerNoCaller) {
		options = append(options, logger.WithoutCaller())
	}
	if v.GetBool(cfgLoggerNoDisclaimer) {
		options = append(options, logger.WithoutDisclaimer())
	}
	l, err := logger.New(options...)
	if err != nil {
		panic(err)
	}
	return l
}
