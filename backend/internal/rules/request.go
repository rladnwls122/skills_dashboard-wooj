// Package rules is the local WAFv2 rule engine, ported from
// src/lib/server/rule*.ts and threatsig.ts. Pure and AWS-free: it evaluates a
// pasted rule against synthetic requests, assembles regex rules from observed
// traffic, and classifies User-Agents. Nothing here makes a network call.
package rules

import (
	"net"
	"net/url"
	"strings"

	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/types"
)

// NormalizedRequest is the synthetic request in the shape the WAFv2 evaluator
// inspects it. Everything a FieldToMatch can point at is resolved here once per
// request — an absent header is a real "no match", not an "unknown".
type NormalizedRequest struct {
	Method  string
	Path    string
	Query   string // without the leading "?"
	Body    string
	IP      string
	Country string
	// lower-cased header name -> value, in declaration order
	Headers *OrderedMap
	// cookie name -> value, parsed from the Cookie header
	Cookies *OrderedMap
	// query arguments in order; names lower-cased, values percent-decoded
	Args []Arg
	// labels visible to this rule (set by the operator or by earlier rules)
	Labels map[string]struct{}
}

type Arg struct{ Name, Value string }

// OrderedMap preserves declaration order the way a JS Map does — HeaderOrder
// and MatchScope:KEY depend on it.
type OrderedMap struct {
	keys []string
	m    map[string]string
}

func NewOrderedMap() *OrderedMap { return &OrderedMap{m: map[string]string{}} }

func (o *OrderedMap) Set(k, v string) {
	if _, ok := o.m[k]; !ok {
		o.keys = append(o.keys, k)
	}
	o.m[k] = v
}

func (o *OrderedMap) Get(k string) (string, bool) { v, ok := o.m[k]; return v, ok }
func (o *OrderedMap) Keys() []string              { return o.keys }
func (o *OrderedMap) Len() int                    { return len(o.keys) }

func (o *OrderedMap) Entries() [][2]string {
	out := make([][2]string, 0, len(o.keys))
	for _, k := range o.keys {
		out = append(out, [2]string{k, o.m[k]})
	}
	return out
}

func (o *OrderedMap) Values() []string {
	out := make([]string, 0, len(o.keys))
	for _, k := range o.keys {
		out = append(out, o.m[k])
	}
	return out
}

func decodeArg(s string) string {
	if d, err := url.QueryUnescape(s); err == nil {
		return d
	}
	return s
}

func parseCookies(header string) *OrderedMap {
	out := NewOrderedMap()
	for _, part := range strings.Split(header, ";") {
		t := strings.TrimSpace(part)
		if t == "" {
			continue
		}
		if eq := strings.IndexByte(t, '='); eq < 0 {
			out.Set(t, "")
		} else {
			out.Set(strings.TrimSpace(t[:eq]), strings.TrimSpace(t[eq+1:]))
		}
	}
	return out
}

func ParseQueryArgs(query string) []Arg {
	out := []Arg{}
	for _, part := range strings.Split(strings.TrimPrefix(query, "?"), "&") {
		if part == "" {
			continue
		}
		name, value := part, ""
		if eq := strings.IndexByte(part, '='); eq >= 0 {
			name, value = part[:eq], part[eq+1:]
		}
		out = append(out, Arg{Name: strings.ToLower(decodeArg(name)), Value: decodeArg(value)})
	}
	return out
}

func NormalizeRequest(req types.TestRequest) *NormalizedRequest {
	headers := NewOrderedMap()
	// The UA has its own column in the sandbox table, so it is authoritative;
	// an empty value means the request carries no User-Agent header at all,
	// which is exactly what AWS's NoUserAgent_HEADER rule looks for.
	if req.UserAgent != "" {
		headers.Set("user-agent", req.UserAgent)
	}
	for name, value := range req.Headers {
		key := strings.ToLower(strings.TrimSpace(name))
		if key == "" || (key == "user-agent" && req.UserAgent != "") {
			continue
		}
		headers.Set(key, value)
	}

	labels := map[string]struct{}{}
	for _, l := range req.Labels {
		labels[l] = struct{}{}
	}

	cookie, _ := headers.Get("cookie")
	return &NormalizedRequest{
		Method:  strings.ToUpper(req.Method),
		Path:    req.Path,
		Query:   strings.TrimPrefix(req.Query, "?"),
		Body:    req.Body,
		IP:      req.IP,
		Country: req.Country,
		Headers: headers,
		Cookies: parseCookies(cookie),
		Args:    ParseQueryArgs(req.Query),
		Labels:  labels,
	}
}

// --- IP / CIDR ---------------------------------------------------------------

// IPInCidr accepts "10.0.0.0/8", "2001:db8::/32" and bare addresses (treated
// as /32 or /128).
func IPInCidr(ip, cidr string) bool {
	addr := net.ParseIP(strings.TrimSpace(ip))
	if addr == nil {
		return false
	}
	c := strings.TrimSpace(cidr)
	if !strings.Contains(c, "/") {
		if strings.Contains(c, ":") {
			c += "/128"
		} else {
			c += "/32"
		}
	}
	_, network, err := net.ParseCIDR(c)
	if err != nil {
		return false
	}
	// A v4 CIDR never contains a v6 address and vice versa (mirrors the TS
	// evaluator, where the two families are parsed separately).
	if (network.IP.To4() == nil) != (addr.To4() == nil) {
		return false
	}
	return network.Contains(addr)
}

var privateRanges = []string{
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
	"169.254.0.0/16", "100.64.0.0/10", "::1/128", "fc00::/7", "fe80::/10",
}

// IsPrivateIP: private / link-local / CGNAT space never appears on an AWS
// reputation list, which lets the managed-group approximation answer "no
// match" instead of "cannot tell" for internal traffic.
func IsPrivateIP(ip string) bool {
	for _, r := range privateRanges {
		if IPInCidr(ip, r) {
			return true
		}
	}
	return false
}
