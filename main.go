// Copyright (c) 2020 Doc.ai and/or its affiliates.
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

package main

import (
	"context"
	"net"
	"net/url"
	"os"
	"time"

	nested "github.com/antonfisher/nested-logrus-formatter"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/kelseyhightower/envconfig"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/networkservicemesh/api/pkg/api/registry"
	"github.com/networkservicemesh/sdk/pkg/networkservice/chains/endpoint"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/authorize"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms/kernel"
	"github.com/networkservicemesh/sdk/pkg/networkservice/ipam/point2pointipam"
	"github.com/networkservicemesh/sdk/pkg/tools/debug"
	"github.com/networkservicemesh/sdk/pkg/tools/grpcutils"
	"github.com/networkservicemesh/sdk/pkg/tools/log"
	"github.com/networkservicemesh/sdk/pkg/tools/signalctx"
	"github.com/networkservicemesh/sdk/pkg/tools/spiffejwt"
)

// Config holds configuration parameters from environment variables
type Config struct {
	Name             string        `default:"icmp-server" desc:"Name of ICMP Server"`
	BaseDir          string        `default:"./" desc:"base directory" split_words:"true"`
	ListenOn         url.URL       `default:"unix:///listen.on.socket" desc:"url to listen on" split_words:"true"`
	ConnectTo        url.URL       `default:"unix:///connect.to.socket" desc:"url to connect to" split_words:"true"`
	MaxTokenLifetime time.Duration `default:"24h" desc:"maximum lifetime of tokens" split_words:"true"`

	EndpointName string `default:"icmp-responder-nse" desc:"url to the local registry to register this NSE"`
	CidrPrefix   string `default:"169.254.0.0/16" desc:"CIDR Prefix to assign IPs from"`
}

func main() {
	// ********************************************************************************
	// setup context to catch signals
	// ********************************************************************************
	ctx := signalctx.WithSignals(context.Background())
	ctx, cancel := context.WithCancel(ctx)

	// ********************************************************************************
	// setup logging
	// ********************************************************************************
	logrus.SetFormatter(&nested.Formatter{})
	logrus.SetLevel(logrus.TraceLevel)
	ctx = log.WithField(ctx, "cmd", os.Args[0])

	if err := debug.Self(); err != nil {
		log.Entry(ctx).Infof("%s", err)
	}

	starttime := time.Now()

	// ********************************************************************************
	log.Entry(ctx).Infof("get config from environment")
	// ********************************************************************************
	config := &Config{}
	if err := envconfig.Usage("nse", config); err != nil {
		logrus.Fatal(err)
	}
	if err := envconfig.Process("nse", config); err != nil {
		logrus.Fatalf("error processing config from env: %+v", err)
	}
	log.Entry(ctx).Infof("Config: %#v", config)

	// ********************************************************************************
	log.Entry(ctx).Infof("retrieving svid, check spire agent logs if this is the last line you see")
	// ********************************************************************************
	source, err := workloadapi.NewX509Source(ctx)
	if err != nil {
		logrus.Fatalf("error getting x509 source: %+v", err)
	}
	svid, err := source.GetX509SVID()
	if err != nil {
		logrus.Fatalf("error getting x509 svid: %+v", err)
	}
	log.Entry(ctx).Infof("SVID: %q", svid.ID)

	// ********************************************************************************
	log.Entry(ctx).Infof("creating icmp server ipam")
	// ********************************************************************************
	_, ipnet, err := net.ParseCIDR(config.CidrPrefix)
	if err != nil {
		log.Entry(ctx).Fatalf("error parsing cidr: %+v", err)
	}

	prefixes := []*net.IPNet{
		ipnet,
	}

	ipamServer := point2pointipam.NewServer(prefixes...)

	// ********************************************************************************
	log.Entry(ctx).Infof("create icmp-server network service endpoint")
	// ********************************************************************************
	responderEndpoint := endpoint.NewServer(
		ctx,
		config.Name,
		authorize.NewServer(),
		spiffejwt.TokenGeneratorFunc(source, config.MaxTokenLifetime),
		ipamServer,
		kernel.NewServer())

	// ********************************************************************************
	log.Entry(ctx).Infof("create grpc server and register icmp-server")
	// TODO add serveroptions for tracing
	// ********************************************************************************
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsconfig.MTLSServerConfig(source, source, tlsconfig.AuthorizeAny()))))
	responderEndpoint.Register(server)
	srvErrCh := grpcutils.ListenAndServe(ctx, &config.ListenOn, server)
	exitOnErr(ctx, cancel, srvErrCh)
	log.Entry(ctx).Infof("grpc server started")

	var nsmTarget string
	switch scheme := config.ConnectTo.Scheme; scheme {
	case "tcp":
		nsmTarget = config.ConnectTo.Host
	default:
		nsmTarget = config.ConnectTo.String()
	}

	// ********************************************************************************
	log.Entry(ctx).Infof("register nse with nsm")
	// ********************************************************************************
	cc, err := grpc.DialContext(ctx,
		nsmTarget,
		grpc.WithBlock(),
		grpc.WithTransportCredentials(credentials.NewTLS(tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeAny()))))
	if err != nil {
		log.Entry(ctx).Fatalf("error establishing grpc connection to registry server %+v", err)
	}

	nse, err := registry.NewNetworkServiceEndpointRegistryClient(cc).Register(context.Background(), &registry.NetworkServiceEndpoint{
		Name:                config.EndpointName,
		NetworkServiceNames: []string{config.Name},
		ExpirationTime:      &timestamp.Timestamp{Seconds: time.Now().Add(time.Hour * 24).Unix()},
	})
	logrus.Infof("nse: %+v", nse)

	if err != nil {
		log.Entry(ctx).Fatalf("unable to register nse %+v", err)
	}
	log.Entry(ctx).Infof("Startup completed in %v", time.Since(starttime))

	// ********************************************************************************
	log.Entry(ctx).Infof("Startup completed in %v", time.Since(starttime))
	// ********************************************************************************
	// wait for server to exit
	<-ctx.Done()
}

func exitOnErr(ctx context.Context, cancel context.CancelFunc, errCh <-chan error) {
	// If we already have an error, log it and exit
	select {
	case err := <-errCh:
		log.Entry(ctx).Fatal(err)
	default:
	}
	// Otherwise wait for an error in the background to log and cancel
	go func(ctx context.Context, errCh <-chan error) {
		err := <-errCh
		log.Entry(ctx).Error(err)
		cancel()
	}(ctx, errCh)
}
