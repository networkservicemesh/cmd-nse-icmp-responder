module github.com/networkservicemesh/cmd-nse-icmp-responder

go 1.16

require (
	github.com/antonfisher/nested-logrus-formatter v1.2.0
	github.com/edwarnicke/exechelper v1.0.2
	github.com/edwarnicke/grpcfd v0.1.0
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/networkservicemesh/api v0.0.0-20210607090113-57f36f2c295b
	github.com/networkservicemesh/sdk v0.0.0-20210609071922-7b63239a9b3b
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.7.0
	github.com/spiffe/go-spiffe/v2 v2.0.0-alpha.4.0.20200528145730-dc11d0c74e85
	github.com/stretchr/testify v1.7.0
	golang.org/x/lint v0.0.0-20200302205851-738671d3881b // indirect
	google.golang.org/genproto v0.0.0-20200615140333-fd031eab31e7 // indirect
	google.golang.org/grpc v1.35.0
	gopkg.in/yaml.v2 v2.3.0 // indirect
)
