package ca

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/smallstep/ca-component/api"
	"github.com/smallstep/ca-component/provisioner"
)

const (
	rootPEM = `-----BEGIN CERTIFICATE-----
MIIEBDCCAuygAwIBAgIDAjppMA0GCSqGSIb3DQEBBQUAMEIxCzAJBgNVBAYTAlVT
MRYwFAYDVQQKEw1HZW9UcnVzdCBJbmMuMRswGQYDVQQDExJHZW9UcnVzdCBHbG9i
YWwgQ0EwHhcNMTMwNDA1MTUxNTU1WhcNMTUwNDA0MTUxNTU1WjBJMQswCQYDVQQG
EwJVUzETMBEGA1UEChMKR29vZ2xlIEluYzElMCMGA1UEAxMcR29vZ2xlIEludGVy
bmV0IEF1dGhvcml0eSBHMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AJwqBHdc2FCROgajguDYUEi8iT/xGXAaiEZ+4I/F8YnOIe5a/mENtzJEiaB0C1NP
VaTOgmKV7utZX8bhBYASxF6UP7xbSDj0U/ck5vuR6RXEz/RTDfRK/J9U3n2+oGtv
h8DQUB8oMANA2ghzUWx//zo8pzcGjr1LEQTrfSTe5vn8MXH7lNVg8y5Kr0LSy+rE
ahqyzFPdFUuLH8gZYR/Nnag+YyuENWllhMgZxUYi+FOVvuOAShDGKuy6lyARxzmZ
EASg8GF6lSWMTlJ14rbtCMoU/M4iarNOz0YDl5cDfsCx3nuvRTPPuj5xt970JSXC
DTWJnZ37DhF5iR43xa+OcmkCAwEAAaOB+zCB+DAfBgNVHSMEGDAWgBTAephojYn7
qwVkDBF9qn1luMrMTjAdBgNVHQ4EFgQUSt0GFhu89mi1dvWBtrtiGrpagS8wEgYD
VR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAQYwOgYDVR0fBDMwMTAvoC2g
K4YpaHR0cDovL2NybC5nZW90cnVzdC5jb20vY3Jscy9ndGdsb2JhbC5jcmwwPQYI
KwYBBQUHAQEEMTAvMC0GCCsGAQUFBzABhiFodHRwOi8vZ3RnbG9iYWwtb2NzcC5n
ZW90cnVzdC5jb20wFwYDVR0gBBAwDjAMBgorBgEEAdZ5AgUBMA0GCSqGSIb3DQEB
BQUAA4IBAQA21waAESetKhSbOHezI6B1WLuxfoNCunLaHtiONgaX4PCVOzf9G0JY
/iLIa704XtE7JW4S615ndkZAkNoUyHgN7ZVm2o6Gb4ChulYylYbc3GrKBIxbf/a/
zG+FA1jDaFETzf3I93k9mTXwVqO94FntT0QJo544evZG0R0SnU++0ED8Vf4GXjza
HFa9llF7b1cq26KqltyMdMKVvvBulRP/F/A8rLIQjcxz++iPAsbw+zOzlTvjwsto
WHPbqCRiOwY1nQ2pM714A5AuTHhdUDqB1O6gyHA43LL5Z/qHQF1hwFGPa4NrzQU6
yuGnBXj8ytqU0CwIPX4WecigUCAkVDNx
-----END CERTIFICATE-----`

	certPEM = `-----BEGIN CERTIFICATE-----
MIIDujCCAqKgAwIBAgIIE31FZVaPXTUwDQYJKoZIhvcNAQEFBQAwSTELMAkGA1UE
BhMCVVMxEzARBgNVBAoTCkdvb2dsZSBJbmMxJTAjBgNVBAMTHEdvb2dsZSBJbnRl
cm5ldCBBdXRob3JpdHkgRzIwHhcNMTQwMTI5MTMyNzQzWhcNMTQwNTI5MDAwMDAw
WjBpMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwN
TW91bnRhaW4gVmlldzETMBEGA1UECgwKR29vZ2xlIEluYzEYMBYGA1UEAwwPbWFp
bC5nb29nbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfRrObuSW5T7q
5CnSEqefEmtH4CCv6+5EckuriNr1CjfVvqzwfAhopXkLrq45EQm8vkmf7W96XJhC
7ZM0dYi1/qOCAU8wggFLMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAa
BgNVHREEEzARgg9tYWlsLmdvb2dsZS5jb20wCwYDVR0PBAQDAgeAMGgGCCsGAQUF
BwEBBFwwWjArBggrBgEFBQcwAoYfaHR0cDovL3BraS5nb29nbGUuY29tL0dJQUcy
LmNydDArBggrBgEFBQcwAYYfaHR0cDovL2NsaWVudHMxLmdvb2dsZS5jb20vb2Nz
cDAdBgNVHQ4EFgQUiJxtimAuTfwb+aUtBn5UYKreKvMwDAYDVR0TAQH/BAIwADAf
BgNVHSMEGDAWgBRK3QYWG7z2aLV29YG2u2IaulqBLzAXBgNVHSAEEDAOMAwGCisG
AQQB1nkCBQEwMAYDVR0fBCkwJzAloCOgIYYfaHR0cDovL3BraS5nb29nbGUuY29t
L0dJQUcyLmNybDANBgkqhkiG9w0BAQUFAAOCAQEAH6RYHxHdcGpMpFE3oxDoFnP+
gtuBCHan2yE2GRbJ2Cw8Lw0MmuKqHlf9RSeYfd3BXeKkj1qO6TVKwCh+0HdZk283
TZZyzmEOyclm3UGFYe82P/iDFt+CeQ3NpmBg+GoaVCuWAARJN/KfglbLyyYygcQq
0SgeDh8dRKUiaW3HQSoYvTvdTuqzwK4CXsr3b5/dAOY8uMuG/IAR3FgwTbZ1dtoW
RvOTa8hYiU6A475WuZKyEHcwnGYe57u2I2KbMgcKjPniocj4QzgYsVAVKW3IwaOh
yE+vPxsiUkvQHdO2fojCkY8jg70jxM+gu59tPDNbw3Uh/2Ij310FgTHsnGQMyA==
-----END CERTIFICATE-----`

	csrPEM = `-----BEGIN CERTIFICATE REQUEST-----
MIIEYjCCAkoCAQAwHTEbMBkGA1UEAxMSdGVzdC5zbWFsbHN0ZXAuY29tMIICIjAN
BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAuCpifZfoZhYNywfpnPa21NezXgtn
wrWBFE6xhVzE7YDSIqtIsj8aR7R8zwEymxfv5j5298LUy/XSmItVH31CsKyfcGqN
QM0PZr9XY3z5V6qchGMqjzt/jqlYMBHujcxIFBfz4HATxSgKyvHqvw14ESsS2huu
7jowx+XTKbFYgKcXrjBkvOej5FXD3ehkg0jDA2UAJNdfKmrc1BBEaaqOtfh7eyU2
HU7+5gxH8C27IiCAmNj719E0B99Nu2MUw6aLFIM4xAcRga33Avevx6UuXZZIEepe
V1sihrkcnDK9Vsxkme5erXzvAoOiRusiC2iIomJHJrdRM5ReEU+N+Tl1Kxq+rk7H
/qAq78wVm07M1/GGi9SUMObZS4WuJpM6whlikIAEbv9iV+CK0sv/Jr/AADdGMmQU
lwk+Q0ZNE8p4ZuWILv/dtLDtDVBpnrrJ9e8duBtB0lGcG8MdaUCQ346EI4T0Sgx0
hJ+wMq8zYYFfPIZEHC8o9p1ywWN9ySpJ8Zj/5ubmx9v2bY67GbuVFEa8iAp+S00x
/Z8nD6/JsoKtexuHyGr3ixWFzlBqXDuugukIDFUOVDCbuGw4Io4/hEMu4Zz0TIFk
Uu/wf2z75Tt8EkosKLu2wieKcY7n7Vhog/0tqexqWlWtJH0tvq4djsGoSvA62WPs
0iXXj+aZIARPNhECAwEAAaAAMA0GCSqGSIb3DQEBCwUAA4ICAQA0vyHIndAkIs/I
Nnz5yZWCokRjokoKv3Aj4VilyjncL+W0UIPULLU/47ZyoHVSUj2t8gknr9xu/Kd+
g/2z0RiF3CIp8IUH49w/HYWaR95glzVNAAzr8qD9UbUqloLVQW3lObSRGtezhdZO
sspw5dC+inhAb1LZhx8PVxB3SAeJ8h11IEBr0s2Hxt9viKKd7YPtIFZkZdOkVx4R
if1DMawj1P6fEomf8z7m+dmbUYTqqosbCbRL01mzEga/kF6JyH/OzpNlcsAiyM8e
BxPWH6TtPqwmyy4y7j1outmM0RnyUw5A0HmIbWh+rHpXiHVsnNqse0XfzmaxM8+z
dxYeDax8aMWZKfvY1Zew+xIxl7DtEy1BpxrZcawumJYt5+LL+bwF/OtL0inQLnw8
zyqydsXNdrpIQJnfmWPld7ThWbQw2FBE70+nFSxHeG2ULnpF3M9xf6ZNAF4gqaNE
Q7vMNPBWrJWu+A++vHY61WGET+h4lY3GFr2I8OE4IiHPQi1D7Y0+fwOmStwuRPM4
2rARcJChNdiYBkkuvs4kixKTTjdXhB8RQtuBSrJ0M1tzq2qMbm7F8G01rOg4KlXU
58jHzJwr1K7cx0lpWfGTtc5bseCGtTKmDBXTziw04yl8eE1+ZFOganixGwCtl4Tt
DCbKzWTW8lqVdp9Kyf7XEhhc2R8C5w==
-----END CERTIFICATE REQUEST-----`
)

func parseCertificate(data string) *x509.Certificate {
	block, _ := pem.Decode([]byte(data))
	if block == nil {
		panic("failed to parse certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("failed to parse certificate: " + err.Error())
	}
	return cert
}

func parseCertificateRequest(data string) *x509.CertificateRequest {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		panic("failed to parse certificate request PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		panic("failed to parse certificate request: " + err.Error())
	}
	return csr
}

func equalJSON(t *testing.T, a interface{}, b interface{}) bool {
	if reflect.DeepEqual(a, b) {
		return true
	}
	ab, err := json.Marshal(a)
	if err != nil {
		t.Error(err)
		return false
	}
	bb, err := json.Marshal(b)
	if err != nil {
		t.Error(err)
		return false
	}
	return bytes.Equal(ab, bb)
}

func TestClient_Health(t *testing.T) {
	ok := &api.HealthResponse{Status: "ok"}
	nok := api.InternalServerError(fmt.Errorf("Internal Server Error"))

	tests := []struct {
		name         string
		response     interface{}
		responseCode int
		wantErr      bool
	}{
		{"ok", ok, 200, false},
		{"not ok", nok, 500, true},
	}

	srv := httptest.NewServer(nil)
	defer srv.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(srv.URL, WithTransport(http.DefaultTransport))
			if err != nil {
				t.Errorf("NewClient() error = %v", err)
				return
			}

			srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				w.WriteHeader(tt.responseCode)
				api.JSON(w, tt.response)
			})

			got, err := c.Health()
			if (err != nil) != tt.wantErr {
				fmt.Printf("%+v", err)
				t.Errorf("Client.Health() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			switch {
			case err != nil:
				if got != nil {
					t.Errorf("Client.Health() = %v, want nil", got)
				}
				if !reflect.DeepEqual(err, tt.response) {
					t.Errorf("Client.Health() error = %v, want %v", err, tt.response)
				}
			default:
				if !reflect.DeepEqual(got, tt.response) {
					t.Errorf("Client.Health() = %v, want %v", got, tt.response)
				}
			}
		})
	}
}

func TestClient_Root(t *testing.T) {
	ok := &api.RootResponse{
		RootPEM: api.Certificate{Certificate: parseCertificate(rootPEM)},
	}
	notFound := api.NotFound(fmt.Errorf("Not Found"))

	tests := []struct {
		name         string
		shasum       string
		response     interface{}
		responseCode int
		wantErr      bool
	}{
		{"ok", "a047a37fa2d2e118a4f5095fe074d6cfe0e352425a7632bf8659c03919a6c81d", ok, 200, false},
		{"not found", "invalid", notFound, 404, true},
	}

	srv := httptest.NewServer(nil)
	defer srv.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(srv.URL, WithTransport(http.DefaultTransport))
			if err != nil {
				t.Errorf("NewClient() error = %v", err)
				return
			}

			srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				expected := "/root/" + tt.shasum
				if req.RequestURI != expected {
					t.Errorf("RequestURI = %s, want %s", req.RequestURI, expected)
				}
				w.WriteHeader(tt.responseCode)
				api.JSON(w, tt.response)
			})

			got, err := c.Root(tt.shasum)
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.Root() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			switch {
			case err != nil:
				if got != nil {
					t.Errorf("Client.Root() = %v, want nil", got)
				}
				if !reflect.DeepEqual(err, tt.response) {
					t.Errorf("Client.Root() error = %v, want %v", err, tt.response)
				}
			default:
				if !reflect.DeepEqual(got, tt.response) {
					t.Errorf("Client.Root() = %v, want %v", got, tt.response)
				}
			}
		})
	}
}

func TestClient_Sign(t *testing.T) {
	ok := &api.SignResponse{
		ServerPEM: api.Certificate{Certificate: parseCertificate(certPEM)},
		CaPEM:     api.Certificate{Certificate: parseCertificate(rootPEM)},
	}
	request := &api.SignRequest{
		CsrPEM:    api.CertificateRequest{CertificateRequest: parseCertificateRequest(csrPEM)},
		OTT:       "the-ott",
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(0, 1, 0),
	}
	unauthorized := api.Unauthorized(fmt.Errorf("Unauthorized"))
	badRequest := api.BadRequest(fmt.Errorf("Bad Request"))

	tests := []struct {
		name         string
		request      *api.SignRequest
		response     interface{}
		responseCode int
		wantErr      bool
	}{
		{"ok", request, ok, 200, false},
		{"unauthorized", request, unauthorized, 401, true},
		{"empty request", &api.SignRequest{}, badRequest, 403, true},
		{"nil request", nil, badRequest, 403, true},
	}

	srv := httptest.NewServer(nil)
	defer srv.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(srv.URL, WithTransport(http.DefaultTransport))
			if err != nil {
				t.Errorf("NewClient() error = %v", err)
				return
			}

			srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				body := new(api.SignRequest)
				if err := api.ReadJSON(req.Body, body); err != nil {
					api.WriteError(w, badRequest)
					return
				} else if !equalJSON(t, body, tt.request) {
					if tt.request == nil {
						if !reflect.DeepEqual(body, &api.SignRequest{}) {
							t.Errorf("Client.Sign() request = %v, wants %v", body, tt.request)
						}
					} else {
						t.Errorf("Client.Sign() request = %v, wants %v", body, tt.request)
					}
				}
				w.WriteHeader(tt.responseCode)
				api.JSON(w, tt.response)
			})

			got, err := c.Sign(tt.request)
			if (err != nil) != tt.wantErr {
				fmt.Printf("%+v", err)
				t.Errorf("Client.Sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			switch {
			case err != nil:
				if got != nil {
					t.Errorf("Client.Sign() = %v, want nil", got)
				}
				if !reflect.DeepEqual(err, tt.response) {
					t.Errorf("Client.Sign() error = %v, want %v", err, tt.response)
				}
			default:
				if !reflect.DeepEqual(got, tt.response) {
					t.Errorf("Client.Sign() = %v, want %v", got, tt.response)
				}
			}
		})
	}
}

func TestClient_Renew(t *testing.T) {
	ok := &api.SignResponse{
		ServerPEM: api.Certificate{Certificate: parseCertificate(certPEM)},
		CaPEM:     api.Certificate{Certificate: parseCertificate(rootPEM)},
	}
	unauthorized := api.Unauthorized(fmt.Errorf("Unauthorized"))
	badRequest := api.BadRequest(fmt.Errorf("Bad Request"))

	tests := []struct {
		name         string
		response     interface{}
		responseCode int
		wantErr      bool
	}{
		{"ok", ok, 200, false},
		{"unauthorized", unauthorized, 401, true},
		{"empty request", badRequest, 403, true},
		{"nil request", badRequest, 403, true},
	}

	srv := httptest.NewServer(nil)
	defer srv.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(srv.URL, WithTransport(http.DefaultTransport))
			if err != nil {
				t.Errorf("NewClient() error = %v", err)
				return
			}

			srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				w.WriteHeader(tt.responseCode)
				api.JSON(w, tt.response)
			})

			got, err := c.Renew(nil)
			if (err != nil) != tt.wantErr {
				fmt.Printf("%+v", err)
				t.Errorf("Client.Renew() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			switch {
			case err != nil:
				if got != nil {
					t.Errorf("Client.Renew() = %v, want nil", got)
				}
				if !reflect.DeepEqual(err, tt.response) {
					t.Errorf("Client.Renew() error = %v, want %v", err, tt.response)
				}
			default:
				if !reflect.DeepEqual(got, tt.response) {
					t.Errorf("Client.Renew() = %v, want %v", got, tt.response)
				}
			}
		})
	}
}

func TestClient_Provisioners(t *testing.T) {
	ok := &api.ProvisionersResponse{
		Provisioners: []*provisioner.Provisioner{},
	}
	internalServerError := api.InternalServerError(fmt.Errorf("Internal Server Error"))

	tests := []struct {
		name         string
		response     interface{}
		responseCode int
		wantErr      bool
	}{
		{"ok", ok, 200, false},
		{"fail", internalServerError, 500, true},
	}

	srv := httptest.NewServer(nil)
	defer srv.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(srv.URL, WithTransport(http.DefaultTransport))
			if err != nil {
				t.Errorf("NewClient() error = %v", err)
				return
			}

			srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				expected := "/provisioners"
				if req.RequestURI != expected {
					t.Errorf("RequestURI = %s, want %s", req.RequestURI, expected)
				}
				w.WriteHeader(tt.responseCode)
				api.JSON(w, tt.response)
			})

			got, err := c.Provisioners()
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.Provisioners() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			switch {
			case err != nil:
				if got != nil {
					t.Errorf("Client.Provisioners() = %v, want nil", got)
				}
				if !reflect.DeepEqual(err, tt.response) {
					t.Errorf("Client.Provisioners() error = %v, want %v", err, tt.response)
				}
			default:
				if !reflect.DeepEqual(got, tt.response) {
					t.Errorf("Client.Provisioners() = %v, want %v", got, tt.response)
				}
			}
		})
	}
}

/*
func TestClient_Provisioners(t *testing.T) {
	ok := &api.ProvisionersResponse{
		Provisioners: map[string]*jose.JSONWebKeySet{},
	}
	internalServerError := api.InternalServerError(fmt.Errorf("Internal Server Error"))

	tests := []struct {
		name         string
		response     interface{}
		responseCode int
		wantErr      bool
	}{
		{"ok", ok, 200, false},
		{"fail", internalServerError, 500, true},
	}

	srv := httptest.NewServer(nil)
	defer srv.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(srv.URL, WithTransport(http.DefaultTransport))
			if err != nil {
				t.Errorf("NewClient() error = %v", err)
				return
			}

			srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				expected := "/provisioners"
				if req.RequestURI != expected {
					t.Errorf("RequestURI = %s, want %s", req.RequestURI, expected)
				}
				w.WriteHeader(tt.responseCode)
				api.JSON(w, tt.response)
			})

			got, err := c.Provisioners()
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.Provisioners() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			switch {
			case err != nil:
				if got != nil {
					t.Errorf("Client.Provisioners() = %v, want nil", got)
				}
				if !reflect.DeepEqual(err, tt.response) {
					t.Errorf("Client.Provisioners() error = %v, want %v", err, tt.response)
				}
			default:
				if !reflect.DeepEqual(got, tt.response) {
					t.Errorf("Client.Provisioners() = %v, want %v", got, tt.response)
				}
			}
		})
	}
}
*/

func TestClient_ProvisionerKey(t *testing.T) {
	ok := &api.ProvisionerKeyResponse{
		Key: "an encrypted key",
	}
	notFound := api.NotFound(fmt.Errorf("Not Found"))

	tests := []struct {
		name         string
		kid          string
		response     interface{}
		responseCode int
		wantErr      bool
	}{
		{"ok", "kid", ok, 200, false},
		{"fail", "invalid", notFound, 500, true},
	}

	srv := httptest.NewServer(nil)
	defer srv.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(srv.URL, WithTransport(http.DefaultTransport))
			if err != nil {
				t.Errorf("NewClient() error = %v", err)
				return
			}

			srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				expected := "/provisioners/" + tt.kid + "/encrypted-key"
				if req.RequestURI != expected {
					t.Errorf("RequestURI = %s, want %s", req.RequestURI, expected)
				}
				w.WriteHeader(tt.responseCode)
				api.JSON(w, tt.response)
			})

			got, err := c.ProvisionerKey(tt.kid)
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.ProvisionerKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			switch {
			case err != nil:
				if got != nil {
					t.Errorf("Client.ProvisionerKey() = %v, want nil", got)
				}
				if !reflect.DeepEqual(err, tt.response) {
					t.Errorf("Client.ProvisionerKey() error = %v, want %v", err, tt.response)
				}
			default:
				if !reflect.DeepEqual(got, tt.response) {
					t.Errorf("Client.ProvisionerKey() = %v, want %v", got, tt.response)
				}
			}
		})
	}
}