package main

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// The bank's own Gateway in front (plans/kubernetes-v2-architecture.md
// §7.1, P8 Phase 2). With gateways.gatewayRef the chart writes three fixed
// routes, all pointing at the AerolVM gateways' Service, in place of its own
// load balancer. Gateway API products differ in what they support, so a
// route the Gateway did not accept is a way in that silently does not work,
// and a sandbox-link listener that ends TLS would decrypt every link at the
// bank's Gateway instead of at the worker. Both are checked.
//
// The routes are found by name, so no flag is needed: an install without
// gatewayRef has none of them and the checks do not apply. Once one exists,
// all three must.

var k8sGatewayRouteKinds = []struct{ kind, resource, suffix string }{
	{"HTTPRoute", "httproutes.gateway.networking.k8s.io", "-api"},
	{"TLSRoute", "tlsroutes.gateway.networking.k8s.io", "-links"},
	{"TCPRoute", "tcproutes.gateway.networking.k8s.io", "-ssh"},
}

// k8sParentRef is a route's reference to its Gateway. Port 0 and an empty
// sectionName mean "any listener".
type k8sParentRef struct {
	Kind        string `json:"kind"`
	Namespace   string `json:"namespace"`
	Name        string `json:"name"`
	SectionName string `json:"sectionName"`
	Port        int    `json:"port"`
}

func (r k8sParentRef) is(o k8sParentRef, routeNamespace string) bool {
	return r.Name == o.Name && cmp.Or(r.Namespace, routeNamespace) == cmp.Or(o.Namespace, routeNamespace) &&
		r.SectionName == o.SectionName && r.Port == o.Port
}

// k8sRoute is the part of an HTTPRoute, TLSRoute or TCPRoute verify reads.
type k8sRoute struct {
	Metadata struct {
		Namespace string `json:"namespace"`
	} `json:"metadata"`
	Spec struct {
		ParentRefs []k8sParentRef `json:"parentRefs"`
		Hostnames  []string       `json:"hostnames"`
	} `json:"spec"`
	Status struct {
		Parents []struct {
			ParentRef  k8sParentRef `json:"parentRef"`
			Conditions []struct {
				Type    string `json:"type"`
				Status  string `json:"status"`
				Reason  string `json:"reason"`
				Message string `json:"message"`
			} `json:"conditions"`
		} `json:"parents"`
	} `json:"status"`
}

// unaccepted names each parent Gateway that has not accepted the route.
// Each controller that serves a parent writes its own status entry, so every
// entry for that parent must say Accepted=True.
func (r k8sRoute) unaccepted() []string {
	if len(r.Spec.ParentRefs) == 0 {
		return []string{"it names no Gateway"}
	}
	var out []string
	for _, ref := range r.Spec.ParentRefs {
		gw := cmp.Or(ref.Namespace, r.Metadata.Namespace) + "/" + ref.Name
		answered := false
		for _, st := range r.Status.Parents {
			if !st.ParentRef.is(ref, r.Metadata.Namespace) {
				continue
			}
			answered = true
			why := "gave no Accepted condition"
			for _, c := range st.Conditions {
				if c.Type == "Accepted" {
					why = ""
					if c.Status != "True" {
						why = fmt.Sprintf("did not accept it (%s: %s)", c.Reason, c.Message)
					}
				}
			}
			if why != "" {
				out = append(out, "Gateway "+gw+" "+why)
			}
		}
		if !answered {
			out = append(out, "Gateway "+gw+" has not answered (no status for it)")
		}
	}
	return out
}

// k8sGatewayRoutes runs the Gateway API checks when the install uses them.
func k8sGatewayRoutes(ctx context.Context, env k8sEnv, o k8sVerifyOptions) []k8sCheck {
	routes := make([]*k8sRoute, len(k8sGatewayRouteKinds))
	missing := make([]string, len(k8sGatewayRouteKinds))
	var unreadable []string
	present := false
	for i, rk := range k8sGatewayRouteKinds {
		name := o.cluster + rk.suffix
		raw, err := env.kubectl(ctx, "get", rk.resource, "-n", o.namespace, "--field-selector", "metadata.name="+name, "-o", "json")
		switch {
		case err != nil && strings.Contains(err.Error(), "doesn't have a resource type"):
			missing[i] = fmt.Sprintf("%s %s: the cluster has no %s (its Gateway API CRD is not installed)", rk.kind, name, rk.kind)
			continue
		case err != nil:
			missing[i] = fmt.Sprintf("%s %s: %v", rk.kind, name, err)
			unreadable = append(unreadable, missing[i])
			continue
		}
		var list struct {
			Items []k8sRoute `json:"items"`
		}
		if err := json.Unmarshal(raw, &list); err != nil {
			missing[i] = fmt.Sprintf("%s %s: kubectl output: %v", rk.kind, name, err)
			unreadable = append(unreadable, missing[i])
			continue
		}
		if len(list.Items) == 0 {
			missing[i] = fmt.Sprintf("%s %s is missing", rk.kind, name)
			continue
		}
		routes[i] = &list.Items[0]
		routes[i].Metadata.Namespace = cmp.Or(routes[i].Metadata.Namespace, o.namespace)
		present = true
	}
	if !present {
		if len(unreadable) > 0 {
			// A role that cannot read routes cannot tell whether they exist,
			// so this is "not checked", not "not used".
			return []k8sCheck{{Name: k8sRoutesAccepted, Result: k8sSkip, Detail: "could not read the routes: " + strings.Join(unreadable, "; ")}}
		}
		return nil
	}
	var bad, ok []string
	for i, rk := range k8sGatewayRouteKinds {
		if routes[i] == nil {
			bad = append(bad, missing[i])
			continue
		}
		name := o.cluster + rk.suffix
		if why := routes[i].unaccepted(); len(why) > 0 {
			bad = append(bad, fmt.Sprintf("%s %s: %s", rk.kind, name, strings.Join(why, "; ")))
			continue
		}
		ok = append(ok, rk.kind+" "+name)
	}
	accepted := k8sCheck{Name: k8sRoutesAccepted, Result: k8sPass, Detail: strings.Join(ok, ", ")}
	if len(bad) > 0 {
		accepted = k8sCheck{Name: k8sRoutesAccepted, Result: k8sFail, Detail: strings.Join(bad, "; ")}
	}
	links := routes[1]
	if links == nil {
		return []k8sCheck{accepted, {Name: k8sLinksPassthrough, Result: k8sFail, Detail: missing[1]}}
	}
	return []k8sCheck{accepted, k8sPassthrough(ctx, env, links)}
}

// k8sGateway is the part of a Gateway verify reads.
type k8sGateway struct {
	Spec struct {
		Listeners []struct {
			Name     string `json:"name"`
			Hostname string `json:"hostname"`
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
			TLS      *struct {
				Mode string `json:"mode"`
			} `json:"tls"`
		} `json:"listeners"`
	} `json:"spec"`
}

// k8sPassthrough follows the sandbox-link TLSRoute to the listeners it
// attaches to and checks each passes TLS through. With no sectionName a
// route attaches to every TLS listener whose hostname meets its own, so a
// bank Gateway's other listeners, for other apps, are left alone. A TLS
// listener with no mode ends TLS: Gateway API's default is Terminate.
func k8sPassthrough(ctx context.Context, env k8sEnv, route *k8sRoute) k8sCheck {
	var bad, ok []string
	for _, ref := range route.Spec.ParentRefs {
		gw := cmp.Or(ref.Namespace, route.Metadata.Namespace) + "/" + ref.Name
		if ref.Kind != "" && ref.Kind != "Gateway" {
			bad = append(bad, fmt.Sprintf("parent %s is a %s, not a Gateway", gw, ref.Kind))
			continue
		}
		raw, err := env.kubectl(ctx, "get", "gateways.gateway.networking.k8s.io", ref.Name, "-n", cmp.Or(ref.Namespace, route.Metadata.Namespace), "-o", "json")
		if err != nil {
			bad = append(bad, fmt.Sprintf("Gateway %s: %v", gw, err))
			continue
		}
		var g k8sGateway
		if err := json.Unmarshal(raw, &g); err != nil {
			bad = append(bad, fmt.Sprintf("Gateway %s: kubectl output: %v", gw, err))
			continue
		}
		matched := 0
		for _, l := range g.Spec.Listeners {
			if (ref.SectionName != "" && l.Name != ref.SectionName) || (ref.Port != 0 && l.Port != ref.Port) {
				continue
			}
			if ref.SectionName == "" && (l.Protocol != "TLS" || !k8sHostsMeet(l.Hostname, route.Spec.Hostnames)) {
				continue
			}
			matched++
			mode := "Terminate"
			if l.TLS != nil && l.TLS.Mode != "" {
				mode = l.TLS.Mode
			}
			where := fmt.Sprintf("Gateway %s listener %s", gw, l.Name)
			if l.Protocol != "TLS" || mode != "Passthrough" {
				bad = append(bad, fmt.Sprintf("%s: protocol %s, mode %s; sandbox links need protocol TLS, mode Passthrough", where, l.Protocol, mode))
				continue
			}
			ok = append(ok, where)
		}
		if matched == 0 {
			bad = append(bad, fmt.Sprintf("Gateway %s has no TLS listener for %s", gw, cmp.Or(strings.Join(route.Spec.Hostnames, ", "), "any name")))
		}
	}
	if len(bad) > 0 {
		return k8sCheck{Name: k8sLinksPassthrough, Result: k8sFail, Detail: strings.Join(bad, "; ")}
	}
	if len(ok) == 0 {
		return k8sCheck{Name: k8sLinksPassthrough, Result: k8sFail, Detail: "the TLSRoute names no Gateway"}
	}
	return k8sCheck{Name: k8sLinksPassthrough, Result: k8sPass, Detail: strings.Join(ok, ", ")}
}

// k8sHostsMeet reports a listener hostname that some of a route's
// hostnames fall under. Empty on either side means any name.
func k8sHostsMeet(listener string, route []string) bool {
	if listener == "" || len(route) == 0 {
		return true
	}
	for _, h := range route {
		if h == listener || k8sWildcardCovers(listener, h) || k8sWildcardCovers(h, listener) {
			return true
		}
	}
	return false
}

// k8sWildcardCovers reports a wildcard w (*.example.com) that matches h, a
// name or another wildcard. Gateway API's wildcard is a suffix match over
// any number of labels: *.example.com matches a.b.example.com.
func k8sWildcardCovers(w, h string) bool {
	suffix, ok := strings.CutPrefix(w, "*.")
	return ok && strings.HasSuffix(strings.TrimPrefix(h, "*"), "."+suffix)
}
