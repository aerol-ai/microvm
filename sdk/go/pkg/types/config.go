package types

import "net/http"

type MicroVMConfig struct {
	PATToken   string
	APIUrl     string
	HTTPClient *http.Client
}
