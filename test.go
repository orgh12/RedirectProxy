package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/gomitmproxy"
	"github.com/AdguardTeam/gomitmproxy/mitm"
	"github.com/AdguardTeam/gomitmproxy/proxyutil"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

type CustomCertsStorage struct {
	// certsCache is a cache with the generated certificates.
	certsCache map[string]*tls.Certificate
}

func (c *CustomCertsStorage) Get(key string) (cert *tls.Certificate, ok bool) {
	cert, ok = c.certsCache[key]

	return cert, ok
}

// Set saves the certificate to the storage.
func (c *CustomCertsStorage) Set(key string, cert *tls.Certificate) {
	c.certsCache[key] = cert
}

func main() {
	// Read the MITM cert and key.
	tlsCert, err := tls.LoadX509KeyPair("C:\\Users\\orshe\\GolandProjects\\demo.crt", "C:\\Users\\orshe\\GolandProjects\\demo.key")
	if err != nil {
		log.Fatal(err)
	}
	privateKey := tlsCert.PrivateKey.(*rsa.PrivateKey)

	x509c, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		log.Fatal(err)
	}

	mitmConfig, err := mitm.NewConfig(x509c, privateKey, &CustomCertsStorage{
		certsCache: map[string]*tls.Certificate{}},
	)

	if err != nil {
		log.Fatal(err)
	}

	// Generate certs valid for 7 days.
	mitmConfig.SetValidity(time.Hour * 24 * 7)
	// Set certs organization.
	mitmConfig.SetOrganization("gomitmproxy")

	// Generate a cert-key pair for the HTTP-over-TLS proxy.
	proxyCert, err := mitmConfig.GetOrCreateCert("127.0.0.1")
	if err != nil {
		panic(err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*proxyCert},
	}

	proxy := gomitmproxy.NewProxy(gomitmproxy.Config{
		ListenAddr: &net.TCPAddr{
			IP:   net.IPv4(0, 0, 0, 0),
			Port: 8080,
		},
		TLSConfig: tlsConfig,
		OnRequest: func(session *gomitmproxy.Session) (request *http.Request, response *http.Response) {
			req := session.Request()

			log.Printf("onRequest: %s %s", req.Method, req.URL.String())
			fmt.Println(req.URL.Host)
			if req.URL.Host == "www.chess.com:443" {
				//body := strings.NewReader("<html><body><h1>Replaced response</h1></body></html>")
				//res := proxyutil.NewResponse(http.StatusOK, body, req)
				//res.Header.Set("Content-Type", "text/html")
				//
				//// Use session props to pass the information about request being blocked
				//session.SetProp("blocked", true)
				resp, err := http.Get("https://www.facebook.com/")
				if err != nil {
					log.Fatal(err)
				}
				res := proxyutil.NewResponse(http.StatusMovedPermanently, resp.Body, nil)
				res.Header.Set("Content-Type", "text/html")
				res.Header.Set("Location", "https://www.facebook.com")
				session.SetProp("blocked", true)
				return nil, res
			}

			return nil, nil
		},
		OnResponse: func(session *gomitmproxy.Session) *http.Response {
			log.Printf("onResponse: %s", session.Request().URL.String())

			if _, ok := session.GetProp("blocked"); ok {
				log.Printf("onResponse: was blocked")
			}

			res := session.Response()
			req := session.Request()

			if strings.Index(res.Header.Get("Content-Type"), "text/html") != 0 {
				// Do nothing with non-HTML responses
				return nil
			}

			b, err := proxyutil.ReadDecompressedBody(res)
			// Close the original body
			_ = res.Body.Close()
			if err != nil {
				return proxyutil.NewErrorResponse(req, err)
			}

			// Use latin1 before modifying the body
			// Using this 1-byte encoding will let us preserve all original characters
			// regardless of what exactly is the encoding
			body, err := proxyutil.DecodeLatin1(bytes.NewReader(b))
			if err != nil {
				return proxyutil.NewErrorResponse(session.Request(), err)
			}

			// Modifying the original body
			modifiedBody, err := proxyutil.EncodeLatin1(body + "<!-- EDITED -->")
			if err != nil {
				return proxyutil.NewErrorResponse(session.Request(), err)
			}

			res.Body = ioutil.NopCloser(bytes.NewReader(modifiedBody))
			res.Header.Del("Content-Encoding")
			res.ContentLength = int64(len(modifiedBody))
			return res
		},
	})
	err = proxy.Start()
	if err != nil {
		log.Fatal(err)
	}

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGTERM)
	<-signalChannel

	// Clean up
	proxy.Close()
}
