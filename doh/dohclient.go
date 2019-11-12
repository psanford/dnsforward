package doh

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/miekg/dns"
)

const dohMimeType = "application/dns-message"

type Client struct {
	serverURL  string
	httpClient *http.Client
}

// New creates a new Client pointed at serverAddr.
// serverURL is the url of the dns server.
// serverAddr should be in the form https://ip:port.
// Specifying the serverName and serverAddr is required
// to avoid needing DNS in order to perform DNS queries.
func New(serverURL string, serverAddr string) (*Client, error) {
	u, err := url.Parse(serverURL)
	if err != nil {
		return nil, fmt.Errorf("parse serverURL: %w", err)
	}

	if u.Scheme != "https" {
		return nil, errors.New("Scheme must be https")
	}

	_, _, err = net.SplitHostPort(serverAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid serverAddr: %w", err)
	}

	conf := tls.Config{
		ServerName: u.Hostname(),
	}

	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		DualStack: true,
	}

	transport := http.Transport{
		ForceAttemptHTTP2: true,
		TLSClientConfig:   &conf,
		DialContext: func(ctx context.Context, network string, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, serverAddr)
		},
	}

	client := http.Client{
		Transport: &transport,
	}

	c := Client{
		serverURL:  serverURL,
		httpClient: &client,
	}
	return &c, nil
}

func (c *Client) Exchange(ctx context.Context, m *dns.Msg) (r *dns.Msg, rtt time.Duration, err error) {
	p, err := m.Pack()
	if err != nil {
		return nil, 0, err
	}

	req, err := http.NewRequest(http.MethodPost, c.serverURL, bytes.NewReader(p))
	if err != nil {
		return nil, 0, err
	}

	req.Header.Set("Content-Type", dohMimeType)
	req.Header.Set("Accept", dohMimeType)

	if ctx != context.Background() && ctx != context.TODO() {
		req = req.WithContext(ctx)
	}

	t := time.Now()

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer closeHTTPBody(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("dns: server returned HTTP %d error: %q", resp.StatusCode, resp.Status)
	}

	if ct := resp.Header.Get("Content-Type"); ct != dohMimeType {
		return nil, 0, fmt.Errorf("dns: unexpected Content-Type %q; expected %q", ct, dohMimeType)
	}

	p, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, err
	}

	rtt = time.Since(t)

	r = new(dns.Msg)
	if err := r.Unpack(p); err != nil {
		return r, 0, err
	}

	return r, rtt, nil
}

func closeHTTPBody(r io.ReadCloser) error {
	io.Copy(ioutil.Discard, io.LimitReader(r, 8<<20))
	return r.Close()
}
