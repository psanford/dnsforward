package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"time"

	"github.com/miekg/dns"
	"github.com/psanford/pnsforward/doh"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	s := newServer()
	server := &dns.Server{
		Net:     "udp",
		Addr:    "localhost:53",
		Handler: s.mux,
	}

	panic(server.ListenAndServe())
}

type server struct {
	mux *dns.ServeMux

	clients []*client
}

func newServer() *server {
	clients := []*client{
		newClassicClient("google", "8.8.8.8:53"),
		// newClassicClient("google", "8.8.4.4:53"),
		newClassicClient("cloudflare", "1.1.1.1:53"),
		// newClassicClient("cloudflare", "1.0.0.1:53"),

		newClassicClient("sonic", "208.201.224.11:53"),
		newClassicClient("sonic", "208.201.224.33:53"),

		// newClassicClient("cloudflare", "2606:4700:4700::1111"),
		// newClassicClient("cloudflare", "2606:4700:4700::1001"),

		newDOHClient("https://dns.google/dns-query", "8.8.8.8:443"),
		// newDOHClient("https://dns.google/dns-query", "8.8.4.4:443"),
		newDOHClient("https://cloudflare-dns.com/dns-query", "1.1.1.1:443"),
	}

	s := &server{
		mux:     dns.NewServeMux(),
		clients: clients,
	}

	s.mux.HandleFunc(".", s.handleRequest)

	return s
}

func (s *server) handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	s.logRequest(r)

	ctx := context.Background()

	ch := make(chan queryResult)
	for _, c := range s.clients {
		c := c
		go func() {
			s.queryBackend(ctx, c, r, ch)
		}()
	}

	done := make(chan struct{})
	go func() {
		var sentResult bool
		for range s.clients {
			result := <-ch
			if !sentResult && result.err == nil {
				w.WriteMsg(result.r)
				s.logFirstResult(r, result)
				close(done)
				sentResult = true
			}

			s.logResult(r, result)
		}
	}()

	<-done

	log.Printf("evt=handle_request_complete")
}

func (s *server) queryBackend(ctx context.Context, c *client, m *dns.Msg, resultChan chan queryResult) {
	t0 := time.Now()
	r, rtt, err := c.exchanger.Exchange(ctx, m)
	resultChan <- queryResult{
		r:         r,
		rtt:       rtt,
		err:       err,
		queryTime: time.Since(t0),
		name:      c.name,
		mode:      c.mode,
		addr:      c.addr,
	}

}

type queryResult struct {
	r         *dns.Msg
	rtt       time.Duration
	err       error
	queryTime time.Duration
	name      string
	mode      transitMode
	addr      string
}

func (s *server) logResult(req *dns.Msg, result queryResult) {
	if result.err != nil {
		log.Printf("evt=backend_result_err req=%s err=%s query_time=%s name=%s mode=%s addr=%s", msg{*req}, result.err, result.queryTime, result.name, result.mode, result.addr)
	} else {
		log.Printf("evt=backend_result req=%s result=%s  query_time=%s name=%s mode=%s addr=%s", msg{*req}, msg{*result.r}, result.queryTime, result.name, result.mode, result.addr)
	}
}

func (s *server) logFirstResult(req *dns.Msg, result queryResult) {
	log.Printf("evt=first_result req=%s result=%s query_time=%s name=%s mode=%s addr=%s", msg{*req}, msg{*result.r}, result.queryTime, result.name, result.mode, result.addr)
}

func (s *server) logRequest(r *dns.Msg) {
	log.Printf("evt=request r=%s", msg{*r})
}

type msg struct {
	dns.Msg
}

func (m msg) String() string {
	var b bytes.Buffer
	fmt.Fprintf(&b, "dnsmsg{")
	for _, q := range m.Question {
		fmt.Fprintf(&b, " q=%s/%s/%s", q.Name, dns.Class(q.Qclass), dns.Type(q.Qtype))
	}
	for _, a := range m.Answer {
		switch v := a.(type) {
		case *dns.A:
			fmt.Fprintf(&b, " aA={%s}", v.A)
		case *dns.AAAA:
			fmt.Fprintf(&b, " aAAAA={%s}", v.AAAA)
		case *dns.CNAME:
			fmt.Fprintf(&b, " aCNAME={%s}", v.Target)
		default:
			fmt.Fprintf(&b, " a={%s}", a)
		}
	}
	fmt.Fprintf(&b, "}")
	return b.String()
}

type transitMode int

const (
	classicTransitMode transitMode = 1
	dohTransitMode     transitMode = 2
)

func (m transitMode) String() string {
	switch m {
	case classicTransitMode:
		return "classic"
	case dohTransitMode:
		return "doh"
	default:
		return fmt.Sprintf("unknown transit mode<%d>", m)
	}
}

type client struct {
	name      string
	mode      transitMode
	exchanger exchanger
	addr      string
}

type exchanger interface {
	Exchange(ctx context.Context, m *dns.Msg) (r *dns.Msg, rtt time.Duration, err error)
}

func newDOHClient(url string, addr string) *client {
	dohClient, err := doh.New(url, addr)
	if err != nil {
		panic(err)
	}
	return &client{
		name:      url,
		addr:      addr,
		mode:      dohTransitMode,
		exchanger: dohClient,
	}
}

func newClassicClient(providerName string, addr string) *client {
	return &client{
		name: providerName,
		mode: classicTransitMode,
		addr: addr,
		exchanger: &classicClient{
			addr: addr,
			c:    &dns.Client{},
		},
	}
}

type classicClient struct {
	addr string
	c    *dns.Client
}

func (c *classicClient) Exchange(ctx context.Context, m *dns.Msg) (r *dns.Msg, rtt time.Duration, err error) {
	return c.c.ExchangeContext(ctx, m, c.addr)
}
