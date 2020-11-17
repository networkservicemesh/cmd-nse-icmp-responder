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

package main_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/edwarnicke/grpcfd"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/networkservicemesh/api/pkg/api/registry"
	"github.com/networkservicemesh/sdk/pkg/registry/common/expire"
	"github.com/networkservicemesh/sdk/pkg/registry/common/recvfd"
	"github.com/networkservicemesh/sdk/pkg/registry/common/setid"
	"github.com/networkservicemesh/sdk/pkg/registry/core/adapters"
	"github.com/networkservicemesh/sdk/pkg/registry/core/chain"
	"github.com/networkservicemesh/sdk/pkg/registry/memory"
	"github.com/networkservicemesh/sdk/pkg/tools/grpcutils"

	nested "github.com/antonfisher/nested-logrus-formatter"
	"github.com/edwarnicke/exechelper"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health/grpc_health_v1"

	main "github.com/networkservicemesh/cmd-nse-icmp-responder"

	"github.com/networkservicemesh/sdk/pkg/tools/spire"
)

type NSESuite struct {
	suite.Suite
	ctx        context.Context
	cancel     context.CancelFunc
	x509source x509svid.Source
	x509bundle x509bundle.Source
	config     main.Config
	spireErrCh <-chan error
	sutErrCh   <-chan error
	listenOn   string
}

func (t *NSESuite) SetupSuite() {
	logrus.SetFormatter(&nested.Formatter{})
	logrus.SetLevel(logrus.TraceLevel)
	t.ctx, t.cancel = context.WithCancel(context.Background())

	// Run spire
	executable, err := os.Executable()
	require.NoError(t.T(), err)
	t.spireErrCh = spire.Start(
		spire.WithContext(t.ctx),
		spire.WithEntry("spiffe://example.org/nse-icmp-responder", "unix:path:/bin/nse-icmp-responder"),
		spire.WithEntry(fmt.Sprintf("spiffe://example.org/%s", filepath.Base(executable)),
			fmt.Sprintf("unix:path:%s", executable),
		),
	)
	require.Len(t.T(), t.spireErrCh, 0)

	// Get X509Source
	source, err := workloadapi.NewX509Source(t.ctx)
	t.x509source = source
	t.x509bundle = source
	require.NoError(t.T(), err)
	svid, err := t.x509source.GetX509SVID()
	if err != nil {
		logrus.Fatalf("error getting x509 svid: %+v", err)
	}
	logrus.Infof("SVID: %q", svid.ID)

	// Run system under test (sut)
	cmdStr := "nse-icmp-responder"
	t.sutErrCh = exechelper.Start(cmdStr,
		exechelper.WithContext(t.ctx),
		exechelper.WithEnvirons(os.Environ()...),
		exechelper.WithStdout(os.Stdout),
		exechelper.WithStderr(os.Stderr),
	)
	require.Len(t.T(), t.sutErrCh, 0)

	// Get config from env
	require.NoError(t.T(), t.config.Process())
	memrg := memory.NewNetworkServiceEndpointRegistryServer()
	registryServer := chain.NewNetworkServiceEndpointRegistryServer(
		setid.NewNetworkServiceEndpointRegistryServer(),
		expire.NewNetworkServiceEndpointRegistryServer(),
		recvfd.NewNetworkServiceEndpointRegistryServer(),
		memrg,
	)

	serverCreds := credentials.NewTLS(tlsconfig.MTLSServerConfig(t.x509source, t.x509bundle, tlsconfig.AuthorizeAny()))
	serverCreds = grpcfd.TransportCredentials(serverCreds)
	server := grpc.NewServer(grpc.Creds(serverCreds))

	registry.RegisterNetworkServiceEndpointRegistryServer(server, registryServer)
	registry.RegisterNetworkServiceRegistryServer(server, memory.NewNetworkServiceRegistryServer())
	ctx, cancel := context.WithCancel(t.ctx)
	defer func(cancel context.CancelFunc, serverErrCh <-chan error) {
		cancel()
		err = <-serverErrCh
		t.Require().NoError(err)
	}(cancel, t.ListenAndServe(ctx, server))

	recv, err := adapters.NetworkServiceEndpointServerToClient(memrg).Find(ctx, &registry.NetworkServiceEndpointQuery{
		NetworkServiceEndpoint: &registry.NetworkServiceEndpoint{
			NetworkServiceNames: []string{t.config.ServiceName},
		},
		Watch: true,
	})
	t.Require().NoError(err)

	regEndpoint, err := recv.Recv()
	t.Require().NoError(err)
	t.listenOn = regEndpoint.Url
}

func (t *NSESuite) ListenAndServe(ctx context.Context, server *grpc.Server) <-chan error {
	errCh := grpcutils.ListenAndServe(ctx, &t.config.ConnectTo, server)
	select {
	case err, ok := <-errCh:
		t.Require().True(ok)
		t.Require().NoError(err)
	default:
	}
	returnErrCh := make(chan error, len(errCh)+1)
	go func(errCh <-chan error, returnErrCh chan<- error) {
		for err := range errCh {
			if err != nil {
				returnErrCh <- errors.Wrap(err, "ListenAndServe")
			}
		}
		close(returnErrCh)
	}(errCh, returnErrCh)
	return returnErrCh
}

func (t *NSESuite) TearDownSuite() {
	t.cancel()
	for {
		_, ok := <-t.sutErrCh
		if !ok {
			break
		}
	}
	for {
		_, ok := <-t.spireErrCh
		if !ok {
			break
		}
	}
}

func (t *NSESuite) TestHealthCheck() {
	ctx, cancel := context.WithTimeout(t.ctx, 100*time.Second)
	defer cancel()
	healthCC, err := grpc.DialContext(ctx,
		t.listenOn,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsconfig.MTLSClientConfig(t.x509source, t.x509bundle, tlsconfig.AuthorizeAny()))),
	)
	if err != nil {
		logrus.Fatalf("Failed healthcheck: %+v", err)
	}
	healthClient := grpc_health_v1.NewHealthClient(healthCC)
	healthResponse, err := healthClient.Check(ctx,
		&grpc_health_v1.HealthCheckRequest{
			Service: "networkservice.NetworkService",
		},
		grpc.WaitForReady(true),
	)
	t.NoError(err)
	t.NotNil(healthResponse)
	t.Equal(grpc_health_v1.HealthCheckResponse_SERVING, healthResponse.Status)
	healthResponse, err = healthClient.Check(ctx,
		&grpc_health_v1.HealthCheckRequest{
			Service: "networkservice.NetworkService",
		},
		grpc.WaitForReady(true),
	)
	t.NoError(err)
	t.NotNil(healthResponse)
	t.Equal(grpc_health_v1.HealthCheckResponse_SERVING, healthResponse.Status)
}

func TestRegistryTestSuite(t *testing.T) {
	suite.Run(t, new(NSESuite))
}
