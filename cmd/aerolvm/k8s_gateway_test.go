package main

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// A sandbox-link route with no parent Gateway.
const k8sOrphanLinks = `{"items":[{"metadata":{"name":"prod-links","namespace":"aerolvm-system"},"spec":{"parentRefs":[],"hostnames":["*.sbx.example.com"]}}]}`

// Each seeded Gateway API problem fails its check (§7.1): a route the
// Gateway did not accept, a route or its CRD missing, and a sandbox-link
// listener that ends TLS.
func TestK8sGatewayFailures(t *testing.T) {
	with := func(edit func(*fakeK8s)) *fakeK8s {
		f := clusterK8s()
		edit(f)
		return f
	}
	links := func(parent, hostnames, conditions string) func(*fakeK8s) {
		return func(f *fakeK8s) { f.routes[k8sTLSRoutes] = k8sRouteJSON("prod-links", parent, hostnames, conditions) }
	}
	const gw = `{"name":"bank-gw","namespace":"infra"}`
	listener := func(old, repl string) func(*fakeK8s) {
		return func(f *fakeK8s) { f.gateways["infra/bank-gw"] = strings.Replace(k8sBankGateway, old, repl, 1) }
	}
	for _, tc := range []struct {
		name, check, want string
		f                 *fakeK8s
	}{
		{name: "a route the Gateway refused", check: k8sRoutesAccepted,
			want: "fail: TLSRoute prod-links: Gateway infra/bank-gw did not accept it (NotAllowedByListeners: no listener allows TLSRoute)",
			f:    with(links(gw, `"*.sbx.example.com"`, `{"type":"Accepted","status":"False","reason":"NotAllowedByListeners","message":"no listener allows TLSRoute"}`))},
		// No namespace on the route or its parent: both are the release
		// namespace.
		{name: "a route no Gateway answered", check: k8sRoutesAccepted, want: "fail: TLSRoute prod-links: Gateway aerolvm-system/bank-gw has not answered (no status for it)",
			f: with(func(f *fakeK8s) {
				f.routes[k8sTLSRoutes] = `{"items":[{"metadata":{"name":"prod-links"},"spec":{"parentRefs":[{"name":"bank-gw"}]},"status":{}}]}`
			})},
		{name: "a status with no Accepted condition", check: k8sRoutesAccepted, want: "fail: TLSRoute prod-links: Gateway infra/bank-gw gave no Accepted condition",
			f: with(links(gw, `"*.sbx.example.com"`, `{"type":"ResolvedRefs","status":"True"}`))},
		{name: "a status for another listener", check: k8sRoutesAccepted, want: "fail: HTTPRoute prod-api: Gateway infra/bank-gw has not answered",
			f: with(func(f *fakeK8s) {
				f.routes[k8sHTTPRoutes] = strings.Replace(f.routes[k8sHTTPRoutes], `"parentRef":{"name":"bank-gw","namespace":"infra","sectionName":"https"}`, `"parentRef":{"name":"bank-gw","namespace":"infra","sectionName":"links"}`, 1)
			})},
		{name: "a route that names no Gateway", check: k8sRoutesAccepted, want: "fail: TLSRoute prod-links: it names no Gateway",
			f: with(func(f *fakeK8s) { f.routes[k8sTLSRoutes] = k8sOrphanLinks })},
		{name: "a route that names no Gateway has no listener", check: k8sLinksPassthrough, want: "fail: the TLSRoute names no Gateway",
			f: with(func(f *fakeK8s) { f.routes[k8sTLSRoutes] = k8sOrphanLinks })},
		{name: "the TLSRoute missing", check: k8sRoutesAccepted, want: "fail: TLSRoute prod-links is missing",
			f: with(func(f *fakeK8s) { f.routes[k8sTLSRoutes] = `{"items":[]}` })},
		{name: "the TLSRoute missing has no listener to follow", check: k8sLinksPassthrough, want: "fail: TLSRoute prod-links is missing",
			f: with(func(f *fakeK8s) { f.routes[k8sTLSRoutes] = `{"items":[]}` })},
		{name: "no TCPRoute CRD", check: k8sRoutesAccepted, want: "fail: TCPRoute prod-ssh: the cluster has no TCPRoute (its Gateway API CRD is not installed)",
			f: with(func(f *fakeK8s) { delete(f.routes, k8sTCPRoutes) })},
		{name: "a route unreadable next to one that exists", check: k8sRoutesAccepted, want: "fail: TCPRoute prod-ssh: forbidden",
			f: with(func(f *fakeK8s) { f.routesErr = map[string]error{k8sTCPRoutes: errors.New("forbidden")} })},
		{name: "routes not JSON", check: k8sRoutesAccepted, want: "fail: HTTPRoute prod-api: kubectl output",
			f: with(func(f *fakeK8s) { f.routes[k8sHTTPRoutes] = "nope" })},
		{name: "routes unreadable and none found", check: k8sRoutesAccepted, want: "skip: could not read the routes: HTTPRoute prod-api: forbidden",
			f: with(func(f *fakeK8s) {
				f.routes = map[string]string{k8sTLSRoutes: `{"items":[]}`}
				f.routesErr = map[string]error{k8sHTTPRoutes: errors.New("forbidden")}
			})},

		{name: "the links listener ends TLS", check: k8sLinksPassthrough,
			want: "fail: Gateway infra/bank-gw listener links: protocol TLS, mode Terminate; sandbox links need protocol TLS, mode Passthrough",
			f:    with(listener(`"tls":{"mode":"Passthrough"}`, `"tls":{"mode":"Terminate"}`))},
		{name: "the links listener with no mode", check: k8sLinksPassthrough, want: "fail: Gateway infra/bank-gw listener links: protocol TLS, mode Terminate",
			f: with(listener(`,"tls":{"mode":"Passthrough"}`, ``))},
		{name: "a sectionName naming the HTTPS listener", check: k8sLinksPassthrough, want: "fail: Gateway infra/bank-gw listener https: protocol HTTPS, mode Terminate",
			f: with(links(`{"name":"bank-gw","namespace":"infra","sectionName":"https"}`, `"*.sbx.example.com"`, k8sAccepted))},
		{name: "a port with no listener", check: k8sLinksPassthrough, want: "fail: Gateway infra/bank-gw has no TLS listener for *.sbx.example.com",
			f: with(links(`{"name":"bank-gw","namespace":"infra","port":8443}`, `"*.sbx.example.com"`, k8sAccepted))},
		{name: "no listener for the links' names", check: k8sLinksPassthrough, want: "fail: Gateway infra/bank-gw has no TLS listener for *.links.example.org",
			f: with(links(gw, `"*.links.example.org"`, k8sAccepted))},
		{name: "a route with no hostnames meets every TLS listener", check: k8sLinksPassthrough, want: "fail: Gateway infra/bank-gw listener other-app: protocol TLS, mode Terminate",
			f: with(links(gw, ``, k8sAccepted))},
		{name: "a parent that is not a Gateway", check: k8sLinksPassthrough, want: "fail: parent infra/bank-gw is a Service, not a Gateway",
			f: with(links(`{"kind":"Service","name":"bank-gw","namespace":"infra"}`, `"*.sbx.example.com"`, k8sAccepted))},
		{name: "the Gateway unreadable", check: k8sLinksPassthrough, want: "fail: Gateway infra/bank-gw: forbidden",
			f: with(func(f *fakeK8s) { f.gateways = nil })},
		{name: "the Gateway not JSON", check: k8sLinksPassthrough, want: "fail: Gateway infra/bank-gw: kubectl output",
			f: with(listener(`{"spec"`, `nope{"spec"`))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := k8sResults(k8sVerify(context.Background(), tc.f.env(), k8sClusterOpts))[tc.check]
			if !strings.HasPrefix(got, tc.want) {
				t.Fatalf("%s = %q, want %q", tc.check, got, tc.want)
			}
		})
	}
}

// With no gatewayRef route, or no Gateway API at all, the route checks do
// not apply: the chart's own load balancer is the way in.
func TestK8sGatewayNotUsed(t *testing.T) {
	for name, routes := range map[string]map[string]string{
		"no Gateway API": nil,
		"no routes":      {k8sHTTPRoutes: `{"items":[]}`, k8sTLSRoutes: `{"items":[]}`, k8sTCPRoutes: `{"items":[]}`},
	} {
		f := clusterK8s()
		f.routes = routes
		got := k8sResults(k8sVerify(context.Background(), f.env(), k8sClusterOpts))
		if _, ok := got[k8sRoutesAccepted]; ok {
			t.Errorf("%s: %q", name, got[k8sRoutesAccepted])
		}
		if _, ok := got[k8sLinksPassthrough]; ok {
			t.Errorf("%s: %q", name, got[k8sLinksPassthrough])
		}
	}
}

func TestK8sHostsMeet(t *testing.T) {
	for _, tc := range []struct {
		listener string
		route    []string
		want     bool
	}{
		{"", []string{"*.sbx.example.com"}, true},
		{"*.sbx.example.com", nil, true},
		{"*.sbx.example.com", []string{"*.sbx.example.com"}, true},
		{"*.example.com", []string{"*.sbx.example.com"}, true},
		{"*.sbx.example.com", []string{"*.example.com"}, true},
		{"*.example.com", []string{"a.b.example.com"}, true},
		{"a.sbx.example.com", []string{"*.sbx.example.com"}, true},
		{"*.example.com", []string{"example.com"}, false},
		{"*.other.example.com", []string{"*.sbx.example.com"}, false},
		{"api.example.com", []string{"*.sbx.example.com", "links.example.org"}, false},
		{"api.example.com", []string{"x.example.org", "api.example.com"}, true},
	} {
		if got := k8sHostsMeet(tc.listener, tc.route); got != tc.want {
			t.Errorf("k8sHostsMeet(%q, %q) = %v, want %v", tc.listener, tc.route, got, tc.want)
		}
	}
}
