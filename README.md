# HTTPD

A small go package to create a golang http application server.

## Features

* pflag integration (can be configured from cobra)
* Unix Domain Socket connections
* HTTP connections
* HTTPS connections

* Optionally can serve the admin endpoints on a different set of listeners

The TLS configuration that is provided is optimized for modern browsers and should get you a perfect A+ score from SSL labs.