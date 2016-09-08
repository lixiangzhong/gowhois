package gowhois

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"strings"
	"time"

	"github.com/Zverushko/punycode"
	"github.com/lixiangzhong/gotool"
)

type whoisServer struct {
	Host    string `json:"host"`
	Adapter string `json:"adapter"` //none, web ,formatted
	URL     string `json:"url"`
	Format  string `json:"format"`
}

var Servers = make(map[string]whoisServer)

func init() {
	err := json.Unmarshal(MustAsset("data.json"), &Servers)
	if err != nil {
		panic(err)
	}
}

func DomainSuffix(domain string) string {
	s := strings.Trim(domain, ".")
	n := strings.Index(s, ".")
	if n < 0 {
		return domain
	}
	return s[n:]
}
func Exchange(domain string, server whoisServer) (result string, err error) {
	if server.Host == "" {
		return "", errors.New(domain + " whois server is nil")
	}
	var query = domain
	if server.Format != "" {
		query = fmt.Sprintf(server.Format, domain)
	}
	return exchange(query, server.Host)
}

func exchange(query string, server string) (result string, err error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(server, "43"), time.Second*10)
	if err != nil {
		return
	}
	conn.Write([]byte(query + "\r\n"))
	buf, err := ioutil.ReadAll(conn)
	if err != nil {
		return
	}
	conn.Close()
	result = string(buf)
	return
}

func Whois(domain string) (result string, err error) {
	domain, err = punycode.ToASCII(domain)
	if err != nil {
		return
	}
	suffix := DomainSuffix(domain)
	var server whoisServer
	var ok bool
	for {
		server, ok = Servers[suffix]
		if suffix == DomainSuffix(suffix) || ok {
			break
		}
		suffix = DomainSuffix(suffix)
	}
	if !ok {
		//没有相应的whois server
		return "", errors.New(domain + " whois server not found")
	}
	return whois(domain, server)
}

func whois(domain string, server whoisServer) (result string, err error) {
	result, err = Exchange(domain, server)
	if err != nil {
		return
	}
	if HasResult(result) {
		return
	}
	realserver, ok := Redirection(result)
	if ok && realserver != server.Host {
		return exchange(domain, realserver)
	}
	return result, nil
}

func Redirection(result string) (string, bool) {
	result = strings.ToLower(result)
	n := strings.Index(result, "domain name:")
	if n < 0 {
		return "", false
	}
	result = result[n:]
	start := strings.Index(result, "whois server:")
	if start < 0 {
		return "", false
	}
	start += 13
	end := strings.Index(result[start:], "\n")
	server := strings.TrimSpace(result[start : start+end])
	server = strings.Trim(server, `/`)
	return server, gotool.IsDomainName(server)
}

func HasResult(result string) bool {
	info := Parse(result)
	return info.Status != nil
}
