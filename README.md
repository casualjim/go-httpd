# HTTPD

A small go package to create a golang http application server.

## Features

* pflag integration (can be configured from cobra)
* Unix Domain Socket connections
* HTTP connections
* HTTPS connections

* Optionally can serve the admin endpoints on a different set of listeners

The TLS configuration that is provided is optimized for modern browsers and should get you a perfect A+ score from SSL labs.

## Usage

```go
package main

import (
  // ... elided...
  "net/http"
  "github.com/NYTimes/gziphandler"

  "github.com/justinas/alice"

  "github.com/e-dard/netbug"

  ghandlers "github.com/gorilla/handlers"
  "github.com/prometheus/client_golang/prometheus/promhttp"
)

var adminServer = &httpd.HTTPFlags{
  Prefix: "admin",
  Port: 12034,
  ListenLimit: 10,
  KeepAlive: 5*time.Second,
  ReadTimeout: 3*time.Second,
  WriteTimeout: 3*time.Second,
}

func main() {
  api := swaggerapi.New(/* ... elided ... */)

  adminHandler := http.NewServeMux()
  netbug.RegisterHandler("/debug/", adminHandler) // trailing slash required in this call
  adminHandler.Handle("/metrics", promhttp.Handler())
  adminHandler.HandleFunc("/healthz", healthzEndpoint)
  adminHandler.HandleFunc("/readyz", readyzEndpoint)
  adminHandler.Handle("/", http.NotFoundHandler())

  ll := &zapLogger{lg: logger.Bg()}
  rhandler := alice.New(
    ghandlers.RecoveryHandler(
      ghandlers.RecoveryLogger(ll),
      ghandlers.PrintRecoveryStack(true),
    ),
    gziphandler.GzipHandler,
    ghandlers.ProxyHeaders,
  ).Then(api.Serve(nil))

  server := httpd.New(
    httpd.LogsWith(ll),
    httpd.HandlesRequestsWith(rhandler),
    httpd.WithAdmin(adminHandler, adminServer),
    httpd.OnShutdown(func() {
      // perform cleanup here
    }),
  )

  if err := server.Listen(); err != nil {
    logger.Bg().Fatal("", zap.Error(err))
  }

  if err := server.Serve(); err != nil {
    logger.Bg().Fatal("", zap.Error(err))
  }
}

func healthzEndpoint(rw http.ResponseWriter, r *http.Request) {
  rw.Write([]byte("OK"))
}

func readyzEndpoint(rw http.ResponseWriter, r *http.Request) {
  rw.Write([]byte("OK"))
}
```