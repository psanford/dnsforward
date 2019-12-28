package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/coreos/go-systemd/v22/activation"
	"github.com/miekg/dns"
	"github.com/psanford/dnsforward/conf"
	"github.com/psanford/dnsforward/doh"
)

var confFile = flag.String("conf", "dnsforward.conf", "Path to config file")

func main() {
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	config, err := conf.Load(*confFile)
	if err != nil {
		panic(err)
	}

	if config.ListenAddr == "" {
		config.ListenAddr = "127.0.0.1:53"
	}

	var pc net.PacketConn
	if config.ListenAddr == "SOCKET_ACTIVATION" {
		listeners, err := activation.PacketConns()
		if err != nil {
			log.Fatalf("Socket activation error, are you running under systemd?: %s", err)
		}
		if len(listeners) == 0 {
			log.Fatalf("No socket provided running in SOCKET_ACTIVATION mode")
		}

		pc = listeners[0]
	}

	s := newServer(config)
	server := &dns.Server{
		Net:     "udp",
		Handler: s.mux,
	}
	if pc != nil {
		server.PacketConn = pc
		panic(server.ActivateAndServe())
	} else {
		server.Addr = config.ListenAddr
		panic(server.ListenAndServe())
	}
}

type server struct {
	mux *dns.ServeMux

	logStream      *json.Encoder
	nextID         uint32
	clients        []*client
	mode           conf.Config_ResolveMode
	logQueries     bool
	localOverrides map[string]string
}

func newServer(config *conf.Config) *server {
	var clients []*client
	for _, s := range config.Servers {
		switch s.Type {
		case conf.Server_UDP:
			clients = append(clients, newClassicClient(s.Name, s.HostPort))
		case conf.Server_DOH:
			clients = append(clients, newDOHClient(s.DohUrl, s.HostPort))
		default:
			log.Fatalf("Invalid server config: %+v", s)
		}
	}

	if len(clients) < 1 {
		log.Fatalf("No backend servers found in config")
	}

	var overrides map[string]string
	if config.OverrideFile != "" {
		var err error
		overrides, err = loadOverrides(config.OverrideFile)
		if err != nil {
			log.Fatalf("Failed to load local overrides: %s", err)
		}
	}

	s := &server{
		mux:            dns.NewServeMux(),
		clients:        clients,
		logStream:      json.NewEncoder(os.Stderr),
		mode:           config.ResolveMode,
		logQueries:     config.LogQueries,
		localOverrides: overrides,
	}

	s.mux.HandleFunc(".", s.handleRequest)

	return s
}

func (s *server) handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	t0 := time.Now()
	idI := atomic.AddUint32(&s.nextID, 1)
	id := fmt.Sprintf("%d-%d", t0.Unix(), idI)
	ctx := context.Background()

	s.logRequest(id, r)

	resp := s.localOverrideResponse(r)
	if resp != nil {
		w.WriteMsg(resp)
		return
	}

	switch s.mode {
	case conf.Config_Random:
		clients := s.shufClients()
		s.handleRequestSerially(ctx, id, w, r, clients)
	case conf.Config_InOrder:
		s.handleRequestSerially(ctx, id, w, r, s.clients)
	case conf.Config_Concurrent:
		s.handleRequestConcurrent(ctx, id, w, r)
	}
}

func (s *server) handleRequestSerially(ctx context.Context, id string, w dns.ResponseWriter, r *dns.Msg, clients []*client) {
	for _, c := range clients {
		result := s.queryBackend(ctx, c, id, r)
		if result.err == nil {
			w.WriteMsg(result.r)
			s.logFirstResult(r, result)
			return
		} else {
			s.logResult(r, result)
		}
	}

	s.logFailure(r, id, len(clients))
}

func (s *server) handleRequestConcurrent(ctx context.Context, id string, w dns.ResponseWriter, r *dns.Msg) {
	ch := make(chan queryResult)
	clients := s.shufClients()
	for _, c := range clients {
		c := c
		go func() {
			ch <- s.queryBackend(ctx, c, id, r)
		}()
	}

	done := make(chan struct{})
	go func() {
		var sentResult bool
		for range clients {
			result := <-ch
			if !sentResult && result.err == nil {
				w.WriteMsg(result.r)
				s.logFirstResult(r, result)
				close(done)
				sentResult = true
			}

			s.logResult(r, result)
		}

		if !sentResult {
			s.logFailure(r, id, len(clients))
		}
	}()

	<-done
}

func (s *server) shufClients() []*client {
	list := make([]*client, len(s.clients))
	copy(list, s.clients)
	rand.Shuffle(len(list), func(i, j int) {
		list[i], list[j] = list[j], list[i]
	})
	return list
}

func (s *server) queryBackend(ctx context.Context, c *client, id string, m *dns.Msg) queryResult {
	t0 := time.Now()
	r, rtt, err := c.exchanger.Exchange(ctx, m)
	return queryResult{
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
	if !s.logQueries {
		return
	}
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

type logFailureMsg struct {
	TS           time.Time `json:"ts"`
	Evt          string    `json:"evt"`
	ID           string    `json:"id"`
	Req          string    `json:"req"`
	BackendCount int       `json:"backend_count"`
}

func (s *server) logFailure(req *dns.Msg, id string, backendCount int) {
	rr := msg{*req}
	m := logFailureMsg{
		TS:           time.Now(),
		Evt:          "query_failure",
		ID:           id,
		Req:          rr.String(),
		BackendCount: backendCount,
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
	if !s.logQueries {
		return
	}
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
	if !s.logQueries {
		return
	}
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

func loadOverrides(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	names := make(map[string]string)

	r := bufio.NewReader(f)
	for {
		line, err := r.ReadString('\n')
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}

		commentStart := strings.Index(line, "#")
		if commentStart >= 0 {
			line = line[:commentStart]
		}

		strings.TrimSpace(line)
		fields := strings.Fields(line)

		if len(fields) < 2 {
			continue
		}
		ip := fields[0]

		for _, name := range fields[1:] {
			if !strings.HasSuffix(name, ".") {
				name = name + "."
			}
			names[name] = ip
		}
	}

	return names, nil
}

func (s *server) localOverrideResponse(r *dns.Msg) *dns.Msg {
	var localOverrideCount int
	localOverrides := make([]net.IP, len(r.Question))
	for i, q := range r.Question {
		if ip := s.localOverrides[q.Name]; ip != "" {
			parsedIP := net.ParseIP(ip)
			if parsedIP == nil {
				continue
			}
			localOverrides[i] = parsedIP
			localOverrideCount++
		}
	}

	if localOverrideCount == len(r.Question) {
		msg := *r
		msg.Response = true
		msg.Answer = make([]dns.RR, len(r.Question))
		for i, ip := range localOverrides {
			if p4 := ip.To4(); len(p4) == net.IPv4len {
				msg.Answer[i] = &dns.A{
					Hdr: dns.RR_Header{
						Name:   r.Question[i].Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    60,
					},
					A: ip,
				}
			} else {
				msg.Answer[i] = &dns.AAAA{
					Hdr: dns.RR_Header{
						Name:   r.Question[i].Name,
						Rrtype: dns.TypeAAAA,
						Class:  dns.ClassINET,
						Ttl:    60,
					},
					AAAA: ip,
				}
			}
		}

		return &msg
	}

	return nil
}
