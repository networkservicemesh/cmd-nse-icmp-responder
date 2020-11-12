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
	"fmt"
	"net"
	"net/url"
	"os"
	"time"

	"github.com/pkg/errors"

	"github.com/networkservicemesh/api/pkg/api/networkservice/payload"

	"github.com/networkservicemesh/sdk/pkg/tools/jaeger"
	"github.com/networkservicemesh/sdk/pkg/tools/spanhelper"

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
	ListenOn         url.URL       `desc:"url to listen on" split_words:"true"`
	ConnectTo        url.URL       `default:"unix:///var/lib/networkservicemesh/nsm.io.sock" desc:"url to connect to" split_words:"true"`
	MaxTokenLifetime time.Duration `default:"24h" desc:"maximum lifetime of tokens" split_words:"true"`
	ServiceName      string        `default:"icmp-responder" desc:"Name of providing service"`
	CidrPrefix       string        `default:"169.254.0.0/16" desc:"CIDR Prefix to assign IPs from"`
}

// Process prints and processes env to config
func (c *Config) Process() error {
	if err := envconfig.Usage("nse", c); err != nil {
		return errors.Wrap(err, "cannot show usage of envconfig nse")
	}
	if err := envconfig.Process("nse", c); err != nil {
		return errors.Wrap(err, "cannot process envconfig nse")
	}
	if c.ListenOn.String() == "" {
		rawURL := fmt.Sprintf("unix:///var/lib/networkservicemesh/%v.nsm.io.sock", c.Name)
		u, err := url.Parse(rawURL)
		if err != nil {
			return errors.Wrapf(err, "cannot parse raw url: %v", rawURL)
		}
		c.ListenOn = *u
	}
	return nil
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

	// ********************************************************************************
	// Configure open tracing
	// ********************************************************************************
	jaegerCloser := jaeger.InitJaeger("cmd-nse-icmp-responder")
	defer func() { _ = jaegerCloser.Close() }()

	// enumerating phases
	log.Entry(ctx).Infof("there are 6 phases which will be executed followed by a success message:")
	log.Entry(ctx).Infof("the phases include:")
	log.Entry(ctx).Infof("1: get config from environment")
	log.Entry(ctx).Infof("2: retrieve spiffe svid")
	log.Entry(ctx).Infof("3: create icmp server ipam")
	log.Entry(ctx).Infof("4: create icmp server nse")
	log.Entry(ctx).Infof("5: create grpc and mount nse")
	log.Entry(ctx).Infof("6: register nse with nsm")
	log.Entry(ctx).Infof("a final success message with start time duration")

	starttime := time.Now()

	// ********************************************************************************
	log.Entry(ctx).Infof("executing phase 1: get config from environment")
	// ********************************************************************************
	config := new(Config)
	if err := config.Process(); err != nil {
		logrus.Fatal(err.Error())
	}

	log.Entry(ctx).Infof("Config: %#v", config)

	// ********************************************************************************
	log.Entry(ctx).Infof("executing phase 2: retrieving svid, check spire agent logs if this is the last line you see")
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
	log.Entry(ctx).Infof("executing phase 3: creating icmp server ipam")
	// ********************************************************************************
	_, ipnet, err := net.ParseCIDR(config.CidrPrefix)
	if err != nil {
		log.Entry(ctx).Fatalf("error parsing cidr: %+v", err)
	}

	prefixes := []*net.IPNet{
		ipnet,
	}

	// ********************************************************************************
	log.Entry(ctx).Infof("executing phase 4: create icmp-server network service endpoint")
	// ********************************************************************************
	responderEndpoint := endpoint.NewServer(
		ctx,
		config.Name,
		authorize.NewServer(),
		spiffejwt.TokenGeneratorFunc(source, config.MaxTokenLifetime),
		point2pointipam.NewServer(prefixes...),
		kernel.NewServer())

	// ********************************************************************************
	log.Entry(ctx).Infof("executing phase 5: create grpc server and register icmp-server")
	// ********************************************************************************
	options := append(
		spanhelper.WithTracing(),
		grpc.Creds(
			credentials.NewTLS(
				tlsconfig.MTLSServerConfig(source, source, tlsconfig.AuthorizeAny()),
			),
		),
	)
	server := grpc.NewServer(options...)
	responderEndpoint.Register(server)
	srvErrCh := grpcutils.ListenAndServe(ctx, &config.ListenOn, server)
	exitOnErr(ctx, cancel, srvErrCh)
	log.Entry(ctx).Infof("grpc server started")

	// ********************************************************************************
	log.Entry(ctx).Infof("executing phase 6: register nse with nsm")
	// ********************************************************************************
	clientOptions := append(
		spanhelper.WithTracingDial(),
		grpc.WithBlock(),
		grpc.WithDefaultCallOptions(grpc.WaitForReady(true)),
		grpc.WithTransportCredentials(
			credentials.NewTLS(
				tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeAny()),
			),
		),
	)
	cc, err := grpc.DialContext(ctx,
		grpcutils.URLToTarget(&config.ConnectTo),
		clientOptions...,
	)
	if err != nil {
		log.Entry(ctx).Fatalf("error establishing grpc connection to registry server %+v", err)
	}

	_, err = registry.NewNetworkServiceRegistryClient(cc).Register(context.Background(), &registry.NetworkService{
		Name:    config.ServiceName,
		Payload: payload.IP,
	})

	if err != nil {
		log.Entry(ctx).Fatalf("unable to register ns %+v", err)
	}

	nse, err := registry.NewNetworkServiceEndpointRegistryClient(cc).Register(context.Background(), &registry.NetworkServiceEndpoint{
		Name:                config.Name,
		NetworkServiceNames: []string{config.ServiceName},
		Url:                 config.ListenOn.String(),
		ExpirationTime:      &timestamp.Timestamp{Seconds: time.Now().Add(time.Hour * 24).Unix()},
	})
	logrus.Infof("nse: %+v", nse)

	if err != nil {
		log.Entry(ctx).Fatalf("unable to register nse %+v", err)
	}

	// ********************************************************************************
	log.Entry(ctx).Infof("startup completed in %v", time.Since(starttime))
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
