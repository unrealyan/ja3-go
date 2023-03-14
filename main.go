package main

import (
	"bufio"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"

	utls "github.com/unrealyan/utls"
)

type ja3Extension struct {
	TLSVersion                uint16
	Ciphers                   []uint16
	Extensions                []uint16
	EllipticCurves            []utls.CurveID
	EllipticCurvePointFormats []uint8
}

var ja3 string

func main() {

	cert, err := utls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		panic(err)
	}

	tlsConfig := &utls.Config{
		PreferServerCipherSuites: true,
		ServerName:               "ja3.ptcl.one",
		NextProtos:               []string{"http/1.1"},
		// CipherSuites: []uint16{
		// 	utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		// 	utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		// 	utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		// },
		MinVersion:             utls.VersionTLS11,
		MaxVersion:             utls.VersionTLS13,
		CurvePreferences:       []utls.CurveID{utls.CurveP256, utls.CurveP384, utls.CurveP521},
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
		Certificates:           []utls.Certificate{cert},
		ClientAuth:             utls.NoClientCert,
		GetCertificate: func(chi *utls.ClientHelloInfo) (*utls.Certificate, error) {
			return &cert, nil
		},
		GetClientCertificate: func(cri *utls.CertificateRequestInfo) (*utls.Certificate, error) {
			return &cert, nil
		},
		GetConfigForClient: func(ch *utls.ClientHelloInfo) (*utls.Config, error) {
			fmt.Println("GetConfigForClientHandler for:", ch.ServerName)
			ja3ext := ja3Extension{
				Ciphers:                   make([]uint16, len(ch.CipherSuites[1:])),
				Extensions:                make([]uint16, len(ch.Extensions[:])),
				EllipticCurves:            make([]utls.CurveID, len(ch.SupportedCurves[1:])),
				EllipticCurvePointFormats: make([]uint8, len(ch.SupportedPoints[:])),
			}
			if len(ch.SupportedVersions) > 0 {
				ja3ext.TLSVersion = ch.SupportedVersions[1]
			}
			copy(ja3ext.Ciphers, ch.CipherSuites[1:])
			copy(ja3ext.Extensions, ch.Extensions[:])
			copy(ja3ext.EllipticCurves, ch.SupportedCurves[1:])
			copy(ja3ext.EllipticCurvePointFormats, ch.SupportedPoints[:])
			ja3 = strconv.Itoa(int(ja3ext.TLSVersion)) + ","
			ciphers := ja3ext.Ciphers
			sort.Slice(ciphers, func(i, j int) bool {
				return ciphers[i] < ciphers[j]
			})
			for _, cipher := range ciphers {
				ja3 += strconv.Itoa(int(cipher)) + "-"
			}
			ja3 = strings.TrimSuffix(ja3, "-") + ","
			extensions := ja3ext.Extensions
			tlsRegistry := []int{2570, 6682, 10794, 14906, 19018, 23130, 27242, 31354, 35466, 39578, 43690, 47802, 51914, 56026, 60138, 64250}

			for i := 0; i < len(extensions); i++ {
				for j := 0; j < len(tlsRegistry); j++ {
					if int(extensions[i]) == tlsRegistry[j] {
						extensions = append(extensions[:i], extensions[i+1:]...)
						i--
						break
					}
				}
			}
			sort.Slice(extensions, func(i, j int) bool {
				return extensions[i] < extensions[j]
			})
			for _, ext := range extensions {
				ja3 += strconv.Itoa(int(ext)) + "-"
			}

			ja3 = strings.TrimSuffix(ja3, "-") + ","
			ellipticCurves := ja3ext.EllipticCurves
			sort.Slice(ellipticCurves, func(i, j int) bool {
				return ellipticCurves[i] < ellipticCurves[j]
			})
			for _, ellipticCurves := range ellipticCurves {
				ja3 += strconv.Itoa(int(ellipticCurves)) + "-"
			}

			ja3 = strings.TrimSuffix(ja3, "-") + ","
			ellipticCurvePointFormats := ja3ext.EllipticCurvePointFormats
			sort.Slice(ellipticCurvePointFormats, func(i, j int) bool {
				return ellipticCurvePointFormats[i] < ellipticCurvePointFormats[j]
			})
			for _, ellipticCurvePointFormats := range ellipticCurvePointFormats {
				ja3 += strconv.Itoa(int(ellipticCurvePointFormats))
			}

			fmt.Println(ja3)

			return nil, nil
		},
	}
	listener, err := utls.Listen("tcp", ":8443", tlsConfig)
	if err != nil {
		panic(err)
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		log.Printf("server: accepted from %s", conn.RemoteAddr())
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	// Read the HTTP request
	req, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		log.Println(err)
		return
	}

	// Extract the necessary information from the request
	path := req.URL.Path

	// Print the request path
	fmt.Println("Request path:", path)
	ja3hash := md5.Sum([]byte(ja3))
	// Send the HTTP response
	response := "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nja3:" + ja3 + "\nja3hash: " + hex.EncodeToString(ja3hash[:]) + "\r\n"
	if _, err := conn.Write([]byte(response)); err != nil {
		log.Println(err)
		return
	}
}
