package controller

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
)

// PortForwarder opens a port-forward from this process to port of pod in
// namespace, as `kubectl port-forward` does, and returns its local base URL
// and the function that closes it. The kubelet connects on the pod's own
// loopback, so the pod counts the call as its own (operator_token.go).
type PortForwarder func(ctx context.Context, namespace, pod string, port int) (baseURL string, stop func(), err error)

// NewPortForwarder is the real PortForwarder, through the API server with
// cfg's credentials (RBAC: create pods/portforward).
func NewPortForwarder(cfg *rest.Config) (PortForwarder, error) {
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	transport, upgrader, err := spdy.RoundTripperFor(cfg)
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context, namespace, pod string, port int) (string, func(), error) {
		u := cs.CoreV1().RESTClient().Post().Resource("pods").Namespace(namespace).Name(pod).SubResource("portforward").URL()
		dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport}, http.MethodPost, u)
		stopCh, readyCh := make(chan struct{}), make(chan struct{})
		fw, err := portforward.NewOnAddresses(dialer, []string{"127.0.0.1"}, []string{"0:" + strconv.Itoa(port)}, stopCh, readyCh, io.Discard, io.Discard)
		if err != nil {
			return "", nil, err
		}
		done := make(chan error, 1)
		go func() { done <- fw.ForwardPorts() }()
		stop := func() { close(stopCh) }
		select {
		case <-readyCh:
		case err := <-done:
			if err == nil {
				err = errors.New("port-forward ended before it was ready")
			}
			return "", nil, err
		case <-ctx.Done():
			stop()
			return "", nil, ctx.Err()
		}
		ports, err := fw.GetPorts()
		if err != nil || len(ports) == 0 {
			stop()
			return "", nil, fmt.Errorf("port-forward to %s/%s has no local port: %v", namespace, pod, err)
		}
		return fmt.Sprintf("http://127.0.0.1:%d", ports[0].Local), stop, nil
	}, nil
}
