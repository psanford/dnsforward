package conf

import (
	"testing"

	"github.com/gogo/protobuf/proto"
	"github.com/google/go-cmp/cmp"
)

var configText = `
resolve_mode: InOrder
server: {
  name: "google"
  type: UDP
  host_port: "8.8.8.8:53"
}
server: {
  name: "cloudflare"
  type: UDP
  host_port: "1.1.1.1:53"
}
server: {
  name: "sonic"
  type: UDP
  host_port: "208.201.224.11:53"
}
server: {
  name: "sonic"
  type: UDP
  host_port: "208.201.224.33:53"
}
server: {
  name: "google"
  type: DOH
  host_port: "8.8.8.8:443"
  doh_url: "https://dns.google/dns-query"
}
server: {
  name: "cloudflare"
  type: DOH
  host_port: "1.1.1.1:443"
  doh_url: "https://cloudflare-dns.com/dns-query"
}
`

func TestConf(t *testing.T) {
	expectServers := []Server{
		{
			Name:     "google",
			Type:     Server_UDP,
			HostPort: "8.8.8.8:53",
		},
		{
			Name:     "cloudflare",
			Type:     Server_UDP,
			HostPort: "1.1.1.1:53",
		},
		{
			Name:     "sonic",
			Type:     Server_UDP,
			HostPort: "208.201.224.11:53",
		},
		{
			Name:     "sonic",
			Type:     Server_UDP,
			HostPort: "208.201.224.33:53",
		},
		{
			Name:     "google",
			Type:     Server_DOH,
			HostPort: "8.8.8.8:443",
			DohUrl:   "https://dns.google/dns-query",
		},
		{
			Name:     "cloudflare",
			Type:     Server_DOH,
			HostPort: "1.1.1.1:443",
			DohUrl:   "https://cloudflare-dns.com/dns-query",
		},
	}

	var conf Config
	err := proto.UnmarshalText(configText, &conf)
	if err != nil {
		t.Fatalf("UnmarshalText error: %s", err)
	}

	if diff := cmp.Diff(expectServers, conf.Servers); diff != "" {
		t.Errorf("Server mismatch (-expect +got):\n%s", diff)
	}
}
