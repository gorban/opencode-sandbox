package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"time"
)

func main() {
	ver := runtime.Version()
	data, _ := os.ReadFile("/w/combos.tsv")
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		f := strings.Split(line, "\t")
		V, L, port, check := f[0], f[1], f[2], f[3]
		pem, _ := os.ReadFile("/w/ca/" + V + "/ca.pem")
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(pem)
		d := net.Dialer{Timeout: 10 * time.Second}
		c, err := tls.DialWithDialer(&d, "tcp", net.JoinHostPort(check, port), &tls.Config{RootCAs: pool, ServerName: check})
		r, det := "OK", ""
		if err != nil {
			r, det = "FAIL", strings.ReplaceAll(err.Error(), "\n", " ")
		} else {
			c.Close()
		}
		fmt.Printf("%s\t%s\t%s\t%s\t%s\n", ver, V, L, r, det)
	}
}
