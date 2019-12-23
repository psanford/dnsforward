dnsforward: A DNS stub resolver with DoH support
==

dnsfoward is a minimal dns stub resolver that supports DNS over HTTPS. Its intended to be run locally so you can get DoH privacy protection for all DNS queries.

I wrote this to address some frustrations I had with existing solutions. Specifically I wanted to be able to profile query latencies between different upstream DNS servers.

## Building

dnsforward requires a go compiler that supports go modules (at least go 1.12). To build checkout this repository and then from the repository's root directory run:

```
GO111MODULE=on go build
```

## Usage

There is an example config file dnsforward.conf.example that demonstrates a basic config. The file format is textproto, the full schema is defined in conf/conf.proto.

The example config starts the server listening on localhost:5300. To run:

```
$ ./dnsforward -conf dnsforward.conf.example
```

Then you can try querying the server:
```
$ nslookup -port=5300 google.com 127.0.0.1
Server:         127.0.0.1
Address:        127.0.0.1#5300

Non-authoritative answer:
Name:   google.com
Address: 172.217.164.110
Name:   google.com
Address: 2607:f8b0:4005:80b::200e

```
