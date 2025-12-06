package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"runtime"

	_ "net/http/pprof"

	"github.com/ginuerzh/gost"
	"github.com/go-log/log"
)

var (
	configureFile string
	baseCfg       = &baseConfig{}
	pprofAddr     string
	pprofEnabled  = os.Getenv("PROFILING") != ""
)

func init() {
	gost.SetLogger(&gost.LogLogger{})

	var (
		printVersion bool
	)

	flag.Var(&baseCfg.route.ChainNodes, "F", "forward address, can make a forward chain")
	flag.Var(&baseCfg.route.ServeNodes, "L", "listen address, can listen on multiple ports (required)")
	flag.IntVar(&baseCfg.route.Mark, "M", 0, "Specify out connection mark")
	flag.StringVar(&configureFile, "C", "", "configure file")
	flag.StringVar(&baseCfg.route.Interface, "I", "", "Interface to bind")
	flag.BoolVar(&baseCfg.Debug, "D", false, "enable debug log")
	flag.BoolVar(&printVersion, "V", false, "print version")
	flag.BoolVar(&baseCfg.EnableTrafficLog, "EnableTrafficLog", false, "enable traffic logging")
	flag.StringVar(&baseCfg.LogDir, "LogDir", "/var/log/gost", "traffic log directory")
	flag.IntVar(&baseCfg.MaxBodyLogBytes, "MaxBodyLogBytes", 65536, "max bytes to capture for request/response body (0=unlimited)")
	flag.StringVar(&baseCfg.RedactHeaders, "RedactHeaders", "Authorization,Cookie", "comma separated headers to redact")
	flag.Float64Var(&baseCfg.SampleRate, "SampleRate", 1.0, "sample rate 0..1 for logging (to reduce volume)")
	flag.BoolVar(&baseCfg.EnableMITM, "EnableMITM", false, "enable HTTPS MITM (requires cert generation and client trust)")

	if pprofEnabled {
		flag.StringVar(&pprofAddr, "P", ":6060", "profiling HTTP server address")
	}
	flag.Parse()

	if printVersion {
		fmt.Fprintf(os.Stdout, "gost %s (%s %s/%s)\n",
			gost.Version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		os.Exit(0)
	}

	if configureFile != "" {
		_, err := parseBaseConfig(configureFile)
		if err != nil {
			log.Log(err)
			os.Exit(1)
		}
	}
	if flag.NFlag() == 0 {
		flag.PrintDefaults()
		os.Exit(0)
	}
}

func main() {
	if pprofEnabled {
		go func() {
			log.Log("profiling server on", pprofAddr)
			log.Log(http.ListenAndServe(pprofAddr, nil))
		}()
	}

	// NOTE: as of 2.6, you can use custom cert/key files to initialize the default certificate.
	tlsConfig, err := tlsConfig(defaultCertFile, defaultKeyFile, "")
	if err != nil {
		// generate random self-signed certificate.
		cert, err := gost.GenCertificate()
		if err != nil {
			log.Log(err)
			os.Exit(1)
		}
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
	} else {
		log.Log("load TLS certificate files OK")
	}

	gost.DefaultTLSConfig = tlsConfig

	if err := start(); err != nil {
		log.Log(err)
		os.Exit(1)
	}

	select {}
}

func start() error {
	gost.Debug = baseCfg.Debug
	gost.EnableTrafficLog = baseCfg.EnableTrafficLog
	gost.LogDir = baseCfg.LogDir
	gost.MaxBodyLogBytes = baseCfg.MaxBodyLogBytes
	gost.RedactHeaders = baseCfg.RedactHeaders
	gost.SampleRate = baseCfg.SampleRate
	gost.EnableMITM = baseCfg.EnableMITM

	var routers []router
	rts, err := baseCfg.route.GenRouters()
	if err != nil {
		return err
	}
	routers = append(routers, rts...)

	for _, route := range baseCfg.Routes {
		rts, err := route.GenRouters()
		if err != nil {
			return err
		}
		routers = append(routers, rts...)
	}

	if len(routers) == 0 {
		return errors.New("invalid config")
	}
	for i := range routers {
		go routers[i].Serve()
	}

	return nil
}
