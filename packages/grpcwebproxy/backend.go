package main

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"time"

	"github.com/mwitkow/grpc-proxy/proxy"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
)

var (
	flagBackendHostPort = pflag.String(
		"backend_addr",
		"",
		"An internal host:port (IP or hostname) of the gRPC server to forward it to (used).")

	flagBackendIsUsingTls = pflag.Bool(
		"backend_tls",
		false,
		"Whether the gRPC server of the backend is serving in plaintext (false) or over TLS (true).",
	)

	flagBackendTlsNoVerify = pflag.Bool(
		"backend_tls_noverify",
		false,
		"Whether to ignore TLS verification checks (cert validity, hostname). *DO NOT USE IN PRODUCTION*.",
	)

	flagBackendTlsClientCert = pflag.String(
		"backend_client_tls_cert_file",
		"",
		"Path to the PEM certificate used when the backend requires client certificates for TLS.")

	flagBackendTlsClientKey = pflag.String(
		"backend_client_tls_key_file",
		"",
		"Path to the PEM key used when the backend requires client certificates for TLS.")

	flagMaxCallRecvMsgSize = pflag.Int(
		"backend_max_call_recv_msg_size",
		1024*1024*100,
		"Maximum receive message size limit. Defaults to 100MB",
	)

	flagBackendTlsCa = pflag.StringSlice(
		"backend_tls_ca_files",
		[]string{},
		"Paths (comma separated) to PEM certificate chains used for verification of backend certificates. If empty, host CA chain will be used.",
	)

	flagBackendDefaultAuthority = pflag.String(
		"backend_default_authority",
		"",
		"Default value to use for the HTTP/2 :authority header commonly used for routing gRPC calls through a backend gateway.",
	)

	flagKeepAliveClientInterval = pflag.Duration(
		"keep_alive_client_interval",
		2*time.Minute,
		"Keep alive client interval. Defaults to 2 minutes",
	)

	flagKeepAliveClientTimeout = pflag.Duration(
		"keep_alive_client_timeout",
		20*time.Second,
		"Keep alive client timeout. Defaults to 20 seconds",
	)

	flagExternalHostPort = pflag.String(
		"external_addr",
		"",
		"An external host:port (IP or hostname) of the gRPC server to forward it to (cosmetic).")

	flagBackendBackoffMaxDelay = pflag.Duration(
		"backend_backoff_max_delay",
		grpc.DefaultBackoffConfig.MaxDelay,
		"Maximum delay when backing off after failed connection attempts to the backend.",
	)
)

func dialBackendOrFail() *grpc.ClientConn {
	if *flagBackendHostPort == "" {
		logrus.Fatalf("flag 'backend_addr' must be set")
	}
	opt := []grpc.DialOption{}
	opt = append(opt, grpc.WithCodec(proxy.Codec()))

	if *flagBackendDefaultAuthority != "" {
		opt = append(opt, grpc.WithAuthority(*flagBackendDefaultAuthority))
	}

	if *flagBackendIsUsingTls {
		opt = append(opt, grpc.WithTransportCredentials(credentials.NewTLS(buildBackendTlsOrFail())))
	} else {
		opt = append(opt, grpc.WithInsecure())
	}

	// keepalive options
	var kap keepalive.ClientParameters
	kap = keepalive.ClientParameters{
		Time:    *flagKeepAliveClientInterval, // https://github.com/grpc/grpc-go/blob/master/keepalive/keepalive.go
		Timeout: *flagKeepAliveClientTimeout}
	kap.PermitWithoutStream = true // this seems important
	opt = append(opt, grpc.WithKeepaliveParams(kap))

	opt = append(opt,
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(*flagMaxCallRecvMsgSize)),
		grpc.WithBackoffMaxDelay(*flagBackendBackoffMaxDelay),
	)

	cc, err := grpc.Dial(*flagBackendHostPort, opt...)
	if err != nil {
		logrus.Fatalf("failed dialing backend: %v", err)
	}
	return cc
}

func buildBackendTlsOrFail() *tls.Config {
	tlsConfig := &tls.Config{}
	tlsConfig.MinVersion = tls.VersionTLS12
	if *flagBackendTlsNoVerify {
		tlsConfig.InsecureSkipVerify = true
	} else {
		if len(*flagBackendTlsCa) > 0 {
			tlsConfig.RootCAs = x509.NewCertPool()
			for _, path := range *flagBackendTlsCa {
				data, err := ioutil.ReadFile(path)
				if err != nil {
					logrus.Fatalf("failed reading backend CA file %v: %v", path, err)
				}
				if ok := tlsConfig.RootCAs.AppendCertsFromPEM(data); !ok {
					logrus.Fatalf("failed processing backend CA file %v", path)
				}
			}
		}
	}
	if *flagBackendTlsClientCert != "" || *flagBackendTlsClientKey != "" {
		if *flagBackendTlsClientCert == "" {
			logrus.Fatal("flag 'backend_client_tls_cert_file' must be set when 'backend_client_tls_key_file' is set")
		}
		if *flagBackendTlsClientKey == "" {
			logrus.Fatal("flag 'backend_client_tls_key_file' must be set when 'backend_client_tls_cert_file' is set")
		}
		cert, err := tls.LoadX509KeyPair(*flagBackendTlsClientCert, *flagBackendTlsClientKey)
		if err != nil {
			logrus.Fatalf("failed reading TLS client keys: %v", err)
		}
		tlsConfig.Certificates = append(tlsConfig.Certificates, cert)
	}
	return tlsConfig
}
