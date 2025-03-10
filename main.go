// Copyright (c) 2020-2023 Doc.ai and/or its affiliates.
//
// Copyright (c) 2021-2023 Nordix and/or its affiliates.
//
// Copyright (c) 2024 OpenInfra Foundation Europe. All rights reserved.
//
// Copyright (c) 2024 Pragmagic Inc. and/or its affiliates.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux
// +build linux

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"gopkg.in/yaml.v2"

	nested "github.com/antonfisher/nested-logrus-formatter"
	"github.com/edwarnicke/grpcfd"
	"github.com/kelseyhightower/envconfig"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/networkservicemesh/api/pkg/api/networkservice"
	kernelmech "github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/kernel"
	"github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/noop"
	registryapi "github.com/networkservicemesh/api/pkg/api/registry"
	sriovtoken "github.com/networkservicemesh/sdk-sriov/pkg/networkservice/common/token"
	"github.com/networkservicemesh/sdk-sriov/pkg/tools/tokens"
	"github.com/networkservicemesh/sdk/pkg/networkservice/chains/endpoint"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/authorize"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms/kernel"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms/sendfd"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/null"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/onidle"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/policyroute"
	"github.com/networkservicemesh/sdk/pkg/networkservice/connectioncontext/dnscontext"
	"github.com/networkservicemesh/sdk/pkg/networkservice/ipam/groupipam"
	"github.com/networkservicemesh/sdk/pkg/networkservice/ipam/strictipam"
	registryclient "github.com/networkservicemesh/sdk/pkg/registry/chains/client"
	registryauthorize "github.com/networkservicemesh/sdk/pkg/registry/common/authorize"
	"github.com/networkservicemesh/sdk/pkg/registry/common/clientinfo"
	registrysendfd "github.com/networkservicemesh/sdk/pkg/registry/common/sendfd"
	"github.com/networkservicemesh/sdk/pkg/tools/cidr"
	"github.com/networkservicemesh/sdk/pkg/tools/debug"
	"github.com/networkservicemesh/sdk/pkg/tools/dnsconfig"
	"github.com/networkservicemesh/sdk/pkg/tools/fs"
	"github.com/networkservicemesh/sdk/pkg/tools/grpcutils"
	"github.com/networkservicemesh/sdk/pkg/tools/log"
	"github.com/networkservicemesh/sdk/pkg/tools/log/logruslogger"
	"github.com/networkservicemesh/sdk/pkg/tools/opentelemetry"
	"github.com/networkservicemesh/sdk/pkg/tools/pprofutils"
	"github.com/networkservicemesh/sdk/pkg/tools/spiffejwt"
	"github.com/networkservicemesh/sdk/pkg/tools/token"
	"github.com/networkservicemesh/sdk/pkg/tools/tracing"
)

// Config holds configuration parameters from environment variables
type Config struct {
	Name                   string            `default:"icmp-server" desc:"Name of ICMP Server"`
	BaseDir                string            `default:"./" desc:"base directory" split_words:"true"`
	ConnectTo              url.URL           `default:"unix:///var/lib/networkservicemesh/nsm.io.sock" desc:"url to connect to" split_words:"true"`
	MaxTokenLifetime       time.Duration     `default:"10m" desc:"maximum lifetime of tokens" split_words:"true"`
	RegistryClientPolicies []string          `default:"etc/nsm/opa/common/.*.rego,etc/nsm/opa/registry/.*.rego,etc/nsm/opa/client/.*.rego" desc:"paths to files and directories that contain registry client policies" split_words:"true"`
	IPAMPolicy             ipamPolicyFunc    `default:"polite" desc:"defines NSE's IPAM Policy. Possible values: polite, strict. Polite policy accepts any addresses sent by client. Strict policy resets ip_context if any of the client's addresses doesn't match endpoint's CIDR." split_words:"true"`
	ServiceNames           []string          `default:"icmp-responder" desc:"Name of provided services" split_words:"true"`
	Payload                string            `default:"ETHERNET" desc:"Name of provided service payload" split_words:"true"`
	Labels                 map[string]string `default:"" desc:"Endpoint labels"`
	DNSConfigs             dnsconfig.Decoder `default:"[]" desc:"DNSConfigs represents array of DNSConfig in json format. See at model definition: https://github.com/networkservicemesh/api/blob/main/pkg/api/networkservice/connectioncontext.pb.go#L426-L435" split_words:"true"`
	CidrPrefix             cidr.Groups       `default:"169.254.0.0/16" desc:"List of CIDR Prefix to assign IPv4 and IPv6 addresses from" split_words:"true"`
	IdleTimeout            time.Duration     `default:"0" desc:"timeout for automatic shutdown when there were no requests for specified time. Set 0 to disable auto-shutdown." split_words:"true"`
	RegisterService        bool              `default:"true" desc:"if true then registers network service on startup" split_words:"true"`
	UnregisterItself       bool              `default:"false" desc:"if true then NSE unregister itself when it completes working" split_words:"true"`
	PBRConfigPath          string            `default:"/etc/policy-based-routing/config.yaml" desc:"Path to policy based routing config file" split_words:"true"`
	LogLevel               string            `default:"INFO" desc:"Log level" split_words:"true"`
	OpenTelemetryEndpoint  string            `default:"otel-collector.observability.svc.cluster.local:4317" desc:"OpenTelemetry Collector Endpoint" split_words:"true"`
	MetricsExportInterval  time.Duration     `default:"10s" desc:"interval between mertics exports" split_words:"true"`
	PprofEnabled           bool              `default:"false" desc:"is pprof enabled" split_words:"true"`
	PprofListenOn          string            `default:"localhost:6060" desc:"pprof URL to ListenAndServe" split_words:"true"`
}

type ipamPolicyFunc func([][]*net.IPNet) networkservice.NetworkServiceServer

// Decode takes a string IPAM Policy and returns the IPAM Policy func
func (f *ipamPolicyFunc) Decode(policy string) error {
	switch strings.ToLower(policy) {
	case "strict":
		*f = func(cidrPrefix [][]*net.IPNet) networkservice.NetworkServiceServer {
			var ipnetList []*net.IPNet
			for _, group := range cidrPrefix {
				ipnetList = append(ipnetList, group...)
			}
			// nolint: revive
			return strictipam.NewServer(func(i ...*net.IPNet) networkservice.NetworkServiceServer {
				return groupipam.NewServer(cidrPrefix)
			}, ipnetList...)
		}
		return nil
	case "polite":
		*f = func(cidrPrefix [][]*net.IPNet) networkservice.NetworkServiceServer {
			return groupipam.NewServer(cidrPrefix)
		}
		return nil
	default:
		return errors.Errorf("not a valid IPAM Policy: %s", policy)
	}
}

// Process prints and processes env to config
func (c *Config) Process() error {
	if err := envconfig.Usage("nsm", c); err != nil {
		return errors.Wrap(err, "cannot show usage of envconfig nse")
	}
	if err := envconfig.Process("nsm", c); err != nil {
		return errors.Wrap(err, "cannot process envconfig nse")
	}
	return nil
}

func main() {
	// ********************************************************************************
	// setup context to catch signals
	// ********************************************************************************
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	signalCtx, _ := signal.NotifyContext(
		ctx,
		os.Interrupt,
		// More Linux signals here
		syscall.SIGHUP,
		syscall.SIGTERM,
		syscall.SIGQUIT,
	)

	// ********************************************************************************
	// setup logging
	// ********************************************************************************
	log.EnableTracing(true)
	logrus.SetFormatter(&nested.Formatter{})
	ctx = log.WithLog(ctx, logruslogger.New(ctx, map[string]interface{}{"cmd": os.Args[0]}))

	if err := debug.Self(); err != nil {
		log.FromContext(ctx).Infof("%s", err)
	}

	// enumerating phases
	log.FromContext(ctx).Infof("there are 6 phases which will be executed followed by a success message:")
	log.FromContext(ctx).Infof("the phases include:")
	log.FromContext(ctx).Infof("1: get config from environment")
	log.FromContext(ctx).Infof("2: retrieve spiffe svid")
	log.FromContext(ctx).Infof("3: create icmp server nse")
	log.FromContext(ctx).Infof("4: create grpc and mount nse")
	log.FromContext(ctx).Infof("5: register nse with nsm")
	log.FromContext(ctx).Infof("a final success message with start time duration")

	starttime := time.Now()

	// ********************************************************************************
	log.FromContext(ctx).Infof("executing phase 1: get config from environment")
	// ********************************************************************************
	config := new(Config)
	if err := config.Process(); err != nil {
		logrus.Fatal(err.Error())
	}
	l, err := logrus.ParseLevel(config.LogLevel)
	if err != nil {
		logrus.Fatalf("invalid log level %s", config.LogLevel)
	}
	logrus.SetLevel(l)
	logruslogger.SetupLevelChangeOnSignal(ctx, map[os.Signal]logrus.Level{
		syscall.SIGUSR1: logrus.TraceLevel,
		syscall.SIGUSR2: l,
	})

	log.FromContext(ctx).Infof("Config: %#v", config)

	// ********************************************************************************
	// Configure Open Telemetry
	// ********************************************************************************
	if opentelemetry.IsEnabled() {
		collectorAddress := config.OpenTelemetryEndpoint
		spanExporter := opentelemetry.InitSpanExporter(ctx, collectorAddress)
		metricExporter := opentelemetry.InitOPTLMetricExporter(ctx, collectorAddress, config.MetricsExportInterval)
		o := opentelemetry.Init(ctx, spanExporter, metricExporter, config.Name)
		defer func() {
			if err = o.Close(); err != nil {
				log.FromContext(ctx).Error(err.Error())
			}
		}()
	}

	// ********************************************************************************
	// Configure pprof
	// ********************************************************************************
	if config.PprofEnabled {
		go pprofutils.ListenAndServe(ctx, config.PprofListenOn)
	}

	// ********************************************************************************
	log.FromContext(ctx).Infof("executing phase 2: retrieving svid, check spire agent logs if this is the last line you see")
	// ********************************************************************************
	source, err := workloadapi.NewX509Source(ctx)
	if err != nil {
		logrus.Fatalf("error getting x509 source: %+v", err)
	}
	svid, err := source.GetX509SVID()
	if err != nil {
		logrus.Fatalf("error getting x509 svid: %+v", err)
	}
	log.FromContext(ctx).Infof("SVID: %q", svid.ID)

	tlsClientConfig := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeAny())
	tlsClientConfig.MinVersion = tls.VersionTLS12
	tlsServerConfig := tlsconfig.MTLSServerConfig(source, source, tlsconfig.AuthorizeAny())
	tlsServerConfig.MinVersion = tls.VersionTLS12

	// ********************************************************************************
	log.FromContext(ctx).Infof("executing phase 3: create icmp-server network service endpoint")
	// ********************************************************************************

	tokenServer := getSriovTokenServerChainElement(ctx)

	responderEndpoint := endpoint.NewServer(ctx,
		spiffejwt.TokenGeneratorFunc(source, config.MaxTokenLifetime),
		endpoint.WithName(config.Name),
		endpoint.WithAuthorizeServer(authorize.NewServer()),
		endpoint.WithAdditionalFunctionality(
			onidle.NewServer(ctx, cancel, config.IdleTimeout),
			config.IPAMPolicy(config.CidrPrefix),
			policyroute.NewServer(newPolicyRoutesGetter(ctx, config.PBRConfigPath).Get),
			mechanisms.NewServer(map[string]networkservice.NetworkServiceServer{
				kernelmech.MECHANISM: kernel.NewServer(),
				noop.MECHANISM:       null.NewServer(),
			}),
			tokenServer,
			dnscontext.NewServer(config.DNSConfigs...),
			sendfd.NewServer(),
		),
	)
	// ********************************************************************************
	log.FromContext(ctx).Infof("executing phase 4: create grpc server and register icmp-server")
	// ********************************************************************************
	options := append(
		tracing.WithTracing(),
		grpc.Creds(
			grpcfd.TransportCredentials(
				credentials.NewTLS(
					tlsServerConfig,
				),
			),
		),
	)
	server := grpc.NewServer(options...)
	responderEndpoint.Register(server)
	tmpDir, err := os.MkdirTemp("", config.Name)
	if err != nil {
		logrus.Fatalf("error creating tmpDir %+v", err)
	}
	defer func(tmpDir string) { _ = os.Remove(tmpDir) }(tmpDir)
	listenOn := &(url.URL{Scheme: "unix", Path: filepath.Join(tmpDir, "listen.on")})
	srvErrCh := grpcutils.ListenAndServe(ctx, listenOn, server)
	exitOnErr(ctx, cancel, srvErrCh)
	log.FromContext(ctx).Infof("grpc server started")

	// ********************************************************************************
	log.FromContext(ctx).Infof("executing phase 5: register nse with nsm")
	// ********************************************************************************
	clientOptions := append(
		tracing.WithTracingDial(),
		grpc.WithBlock(),
		grpc.WithDefaultCallOptions(
			grpc.WaitForReady(true),
			grpc.PerRPCCredentials(token.NewPerRPCCredentials(spiffejwt.TokenGeneratorFunc(source, config.MaxTokenLifetime)))),
		grpc.WithTransportCredentials(
			grpcfd.TransportCredentials(
				credentials.NewTLS(
					tlsClientConfig,
				),
			),
		),
		grpcfd.WithChainStreamInterceptor(),
		grpcfd.WithChainUnaryInterceptor(),
	)

	if config.RegisterService {
		for _, serviceName := range config.ServiceNames {
			nsRegistryClient := registryclient.NewNetworkServiceRegistryClient(ctx,
				registryclient.WithClientURL(&config.ConnectTo),
				registryclient.WithDialOptions(clientOptions...),
				registryclient.WithAuthorizeNSRegistryClient(registryauthorize.NewNetworkServiceRegistryClient(
					registryauthorize.WithPolicies(config.RegistryClientPolicies...))))
			_, err = nsRegistryClient.Register(ctx, &registryapi.NetworkService{
				Name:    serviceName,
				Payload: config.Payload,
			})

			if err != nil {
				log.FromContext(ctx).Fatalf("unable to register ns %+v", err)
			}
		}
	}

	nseRegistryClient := registryclient.NewNetworkServiceEndpointRegistryClient(
		ctx,
		registryclient.WithClientURL(&config.ConnectTo),
		registryclient.WithDialOptions(clientOptions...),
		registryclient.WithNSEAdditionalFunctionality(
			clientinfo.NewNetworkServiceEndpointRegistryClient(),
			registrysendfd.NewNetworkServiceEndpointRegistryClient(),
		),
		registryclient.WithAuthorizeNSERegistryClient(registryauthorize.NewNetworkServiceEndpointRegistryClient(
			registryauthorize.WithPolicies(config.RegistryClientPolicies...))),
	)
	nse := getNseEndpoint(config, listenOn)
	nse, err = nseRegistryClient.Register(ctx, nse)
	logrus.Infof("nse: %+v", nse)

	if err != nil {
		log.FromContext(ctx).Fatalf("unable to register nse %+v", err)
	}

	if config.UnregisterItself {
		defer func() {
			_, err = nseRegistryClient.Unregister(context.Background(), nse)
			if err != nil {
				log.FromContext(ctx).Errorf("nse failed to unregister itself on termination: %s", err.Error())
			}
		}()
	}
	// ********************************************************************************
	log.FromContext(ctx).Infof("startup completed in %v", time.Since(starttime))
	// ********************************************************************************

	// wait for server to exit
	<-signalCtx.Done()
}

func getNseEndpoint(config *Config, listenOn fmt.Stringer) *registryapi.NetworkServiceEndpoint {
	nse := &registryapi.NetworkServiceEndpoint{
		Name:                 config.Name,
		NetworkServiceNames:  config.ServiceNames,
		NetworkServiceLabels: make(map[string]*registryapi.NetworkServiceLabels),
		Url:                  listenOn.String(),
	}
	for _, serviceName := range config.ServiceNames {
		nse.NetworkServiceLabels[serviceName] = &registryapi.NetworkServiceLabels{Labels: config.Labels}
	}
	return nse
}

func getSriovTokenServerChainElement(ctx context.Context) (tokenServer networkservice.NetworkServiceServer) {
	sriovTokens := tokens.FromEnv(os.Environ())
	switch len(sriovTokens) {
	case 0:
		tokenServer = null.NewServer()
	case 1:
		var tokenKey string
		for tokenKey = range sriovTokens {
			break
		}
		tokenServer = sriovtoken.NewServer(tokenKey)
	default:
		log.FromContext(ctx).Fatalf("endpoint must be configured with none or only one sriov resource")
	}
	return
}

func exitOnErr(ctx context.Context, cancel context.CancelFunc, errCh <-chan error) {
	// If we already have an error, log it and exit
	select {
	case err := <-errCh:
		log.FromContext(ctx).Fatal(err)
	default:
	}
	// Otherwise wait for an error in the background to log and cancel
	go func(ctx context.Context, errCh <-chan error) {
		err := <-errCh
		log.FromContext(ctx).Error(err)
		cancel()
	}(ctx, errCh)
}

// newPolicyRoutesGetter - watches the config file and dynamically updates policy routes.
func newPolicyRoutesGetter(ctx context.Context, configPath string) *policyRoutesGetter {
	p := &policyRoutesGetter{
		ctx: ctx,
	}
	p.policyRoutes.Store([]*networkservice.PolicyRoute{})
	updatePrefixes := func(bytes []byte) {
		if bytes == nil {
			p.policyRoutes.Store([]*networkservice.PolicyRoute{})
		}
		var source []*networkservice.PolicyRoute
		err := yaml.Unmarshal(bytes, &source)
		if err != nil {
			log.FromContext(ctx).Errorf("Cannot unmarshal policies, err: %v", err.Error())
			return
		}
		p.policyRoutes.Store(source)
	}
	updateCh := fs.WatchFile(p.ctx, configPath)
	updatePrefixes(<-updateCh)
	go func() {
		for {
			select {
			case <-p.ctx.Done():
				return
			case update := <-updateCh:
				updatePrefixes(update)
			}
		}
	}()

	return p
}

func (p *policyRoutesGetter) Get() []*networkservice.PolicyRoute {
	return p.policyRoutes.Load().([]*networkservice.PolicyRoute)
}

type policyRoutesGetter struct {
	ctx          context.Context
	policyRoutes atomic.Value
}
