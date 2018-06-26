package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/lucas-clemente/quic-go"
)

func server(host string) {
	listener, err := quic.ListenAddr(host, generateTLSConfig(), nil)
	if err != nil {
		fmt.Printf("listen quic: %v", err)
		return
	}
	for {
		sess, err := listener.Accept()
		if err != nil {
			fmt.Println(err)
			continue
		}
		stream, err := sess.AcceptStream()
		if err != nil {
			fmt.Println(err)
			continue
		}
		read, err := io.Copy(ioutil.Discard, stream)
		fmt.Println("Read: ", read, err)
		stream.Write([]byte(fmt.Sprintf("%v", read)))
		sess.Close(stream.Close())
	}
}

type InfReader struct{}

func (r InfReader) Read(b []byte) (int, error) {
	// for i := range b {
	// 	b[i] = 'A'
	// }
	return len(b), nil
}

func main() {
	isServer := flag.Bool("server", false, "")
	host := flag.String("host", "127.0.0.1", "")
	timeLimit := flag.String("limit", "10s", "spend at most this much time on the test.")
	hostPort := flag.String("port", "9999", "")
	flag.Parse()
	if !strings.Contains(*host, ":") {
		*host += ":" + *hostPort
	}
	tl, err := time.ParseDuration(*timeLimit)
	if err != nil || tl == 0 {
		tl = 10 * time.Second
	}

	if *isServer {
		server(*host)
		return
	}

	session, err := quic.DialAddr(*host, &tls.Config{InsecureSkipVerify: true}, nil)
	if err != nil {
		panic(err)
	}

	stream, err := session.OpenStream()
	if err != nil {
		panic(err)
	}

	ss := 1024 * 1024 * 1024
	sends := make([]byte, ss)

	for i := 0; i < ss; i++ {
		sends[i] = 100
	}

	//buf := bytes.NewBuffer(sends)
	go func() {
		time.Sleep(tl)
		fmt.Println("Truncing...?")
		stream.Close()
		session.Close(nil)
	}()

	s := time.Now()
	n, err := io.Copy(stream, InfReader{})
	t := time.Since(s)
	stream.Close()
	session.Close(err)

	if err != nil && n <= 0 {
		fmt.Fprintln(os.Stderr, "error sending to server: ", err)
		fmt.Println("-1")
		return
	}
	fmt.Printf("Duration: %v, Sent: %v, bps: %v, mbps: %v\n", t, n, float64(n)/t.Seconds(), float64(n)/(t.Seconds()*1024*1024))

	/*stream.SetReadDeadline(time.Now().Add(2 * time.Second))
	data := make([]byte, 1000)
	r, err := stream.Read(data)
	data = data[:r]
	dur, err := strconv.ParseInt(string(data), 10, 64)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error Receiving amount from Server", err)
		return
	}
	fmt.Printf("Duration: %v, Sent: %v, bps: %v, mbps: %v\n", dur, n, float64(n)/dur.Seconds(), float64(n)/(dur.Seconds()*1024*1024))
	*/

}

// Setup a bare-bones TLS config for the server
func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{tlsCert}}
}
