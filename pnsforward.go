package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync/atomic"
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

	logStream *json.Encoder
	nextID    uint32
	clients   []*client
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
		mux:       dns.NewServeMux(),
		clients:   clients,
		logStream: json.NewEncoder(os.Stderr),
	}

	s.mux.HandleFunc(".", s.handleRequest)

	return s
}

func (s *server) handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	t0 := time.Now()
	idI := atomic.AddUint32(&s.nextID, 1)
	id := fmt.Sprintf("%d-%d", idI, t0.Unix())

	s.logRequest(id, r)

	ctx := context.Background()

	ch := make(chan queryResult)
	for _, c := range s.clients {
		c := c
		go func() {
			s.queryBackend(ctx, c, id, r, ch)
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

func (s *server) queryBackend(ctx context.Context, c *client, id string, m *dns.Msg, resultChan chan queryResult) {
	t0 := time.Now()
	r, rtt, err := c.exchanger.Exchange(ctx, m)
	resultChan <- queryResult{
		r:         r,
		id:        id,
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
	id        string
	rtt       time.Duration
	err       error
	queryTime time.Duration
	name      string
	mode      transitMode
	addr      string
}

type logResultMsg struct {
	TS          time.Time `json:"ts"`
	Evt         string    `json:"evt"`
	ID          string    `json:"id"`
	DurationUS  int64     `json:"duration_us"`
	Backend     string    `json:"backend"`
	Mode        string    `json:"mode"`
	BackendAddr string    `json:"backend_addr"`
	Error       error     `json:"error,omitempty"`
	Req         string    `json:"req"`
}

func (s *server) logResult(req *dns.Msg, result queryResult) {
	rr := msg{*req}
	m := logResultMsg{
		TS:          time.Now(),
		Evt:         "backend_result",
		ID:          result.id,
		DurationUS:  result.queryTime.Microseconds(),
		Backend:     result.name,
		Mode:        result.mode.String(),
		BackendAddr: result.addr,
		Error:       result.err,
		Req:         rr.String(),
	}

	s.logJSON(m)
}

func (s *server) logJSON(m interface{}) {
	s.logStream.Encode(m)
}

type logFirstResultMsg struct {
	TS          time.Time `json:"ts"`
	Evt         string    `json:"evt"`
	ID          string    `json:"id"`
	DurationUS  int64     `json:"duration_us"`
	Backend     string    `json:"backend"`
	Mode        string    `json:"mode"`
	BackendAddr string    `json:"backend_addr"`
	Result      string    `json:"result"`
}

func (s *server) logFirstResult(req *dns.Msg, result queryResult) {
	rr := msg{*result.r}

	m := logFirstResultMsg{
		TS:          time.Now(),
		Evt:         "first_result",
		ID:          result.id,
		DurationUS:  result.queryTime.Microseconds(),
		Backend:     result.name,
		Mode:        result.mode.String(),
		BackendAddr: result.addr,
		Result:      rr.String(),
	}

	s.logJSON(m)
}

type logRequest struct {
	TS  time.Time `json:"ts"`
	Evt string    `json:"evt"`
	ID  string    `json:"id"`
	Req string    `json:"req"`
}

func (s *server) logRequest(id string, req *dns.Msg) {
	rr := msg{*req}
	m := logResultMsg{
		TS:  time.Now(),
		Evt: "request",
		ID:  id,
		Req: rr.String(),
	}

	s.logJSON(m)
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
