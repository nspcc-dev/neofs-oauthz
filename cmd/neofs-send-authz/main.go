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
