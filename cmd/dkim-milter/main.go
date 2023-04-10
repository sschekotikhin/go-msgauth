package main

import (
	"bytes"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/mail"
	"net/textproto"
	"os"
	"os/signal"
	"path"
	"strings"
	"syscall"

	"github.com/emersion/go-milter"
	"github.com/sschekotikhin/go-msgauth/authres"
	"github.com/sschekotikhin/go-msgauth/dkim"
	"github.com/sschekotikhin/openssl"
)

var (
	signDomains    stringSliceFlag
	identity       string
	listenURI      string
	privateKeyPath string
	selector       string
	verbose        bool
)

var privateKey openssl.PrivateKey

var signHeaderKeys = []string{
	"From",
	"Reply-To",
	"Subject",
	"Date",
	"To",
	"Cc",
	"Resent-Date",
	"Resent-From",
	"Resent-To",
	"Resent-Cc",
	"In-Reply-To",
	"References",
	"List-Id",
	"List-Help",
	"List-Unsubscribe",
	"List-Subscribe",
	"List-Post",
	"List-Owner",
	"List-Archive",
}

const maxVerifications = 5

func init() {
	flag.Var(&signDomains, "d", "Domain(s) whose mail should be signed (matched using path.Match)")
	flag.StringVar(&identity, "i", "", "Server identity (defaults to hostname)")
	flag.StringVar(&listenURI, "l", "unix:///tmp/dkim-milter.sock", "Listen URI")
	flag.StringVar(&privateKeyPath, "k", "", "Private key (PEM-formatted)")
	flag.StringVar(&selector, "s", "", "Selector")
	flag.BoolVar(&verbose, "v", false, "Enable verbose logging")
}

type stringSliceFlag []string

func (f *stringSliceFlag) String() string {
	return strings.Join(*f, ", ")
}

func (f *stringSliceFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}

type session struct {
	milter.NoOpMilter

	authResDelete []int
	headerBuf     bytes.Buffer

	signDomain     string
	signHeaderKeys []string

	done   <-chan error
	pw     *io.PipeWriter
	verifs []*dkim.Verification // only valid after done is closed
	signer *dkim.Signer
	mw     io.Writer
}

func parseAddressDomain(s string) (string, error) {
	addr, err := mail.ParseAddress(s)
	if err != nil {
		return "", err
	}

	parts := strings.SplitN(addr.Address, "@", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("dkim-milter: malformed address: missing '@'")
	}

	return parts[1], nil
}

func (s *session) Header(name string, value string, m *milter.Modifier) (milter.Response, error) {
	if strings.EqualFold(name, "From") || strings.EqualFold(name, "Sender") {
		domain, err := parseAddressDomain(value)
		if err != nil {
			return nil, fmt.Errorf("dkim-milter: failed to parse header field %q: %v", name, err)
		}
		domain = strings.ToLower(domain)

		for _, pattern := range signDomains {
			if ok, err := path.Match(pattern, domain); err != nil {
				return nil, fmt.Errorf("dkim-milter: failed to match domain %q: %v", domain, err)
			} else if ok {
				s.signDomain = domain
				break
			}
		}
	}

	for _, k := range signHeaderKeys {
		if strings.EqualFold(name, k) {
			s.signHeaderKeys = append(s.signHeaderKeys, name)
		}
	}

	field := name + ": " + value + "\r\n"
	_, err := s.headerBuf.WriteString(field)
	return milter.RespContinue, err
}

func getIdentity(authRes string) string {
	parts := strings.SplitN(authRes, ";", 2)
	return strings.TrimSpace(parts[0])
}

func shouldDeleteAuthRes(field string) bool {
	id, results, err := authres.Parse(field)
	if err != nil {
		// Delete fields we can't parse, because other implementations might
		// accept malformed fields
		return true
	}

	if !strings.EqualFold(id, identity) {
		// Not our Authentication-Results, ignore the field
		return false
	}

	for _, res := range results {
		if _, ok := res.(*authres.DKIMResult); ok {
			// Delete existing DKIM Authentication-Results fields
			return true
		}
	}

	// This is our Authentication-Results field, but it isn't about DKIM. Maybe
	// a previous milter has generated it (e.g. SPF), so keep it.
	return false
}

func (s *session) Headers(h textproto.MIMEHeader, m *milter.Modifier) (milter.Response, error) {
	// Write final CRLF to begin message body
	if _, err := s.headerBuf.WriteString("\r\n"); err != nil {
		return nil, err
	}

	// Delete any existing Authentication-Results header field with our identity
	fields := h["Authentication-Results"]
	for i, field := range fields {
		if shouldDeleteAuthRes(field) {
			s.authResDelete = append(s.authResDelete, i)
		}
	}

	// Sign if necessary
	if s.signDomain != "" {
		opts := dkim.SignOptions{
			Domain:       s.signDomain,
			Selector:     selector,
			Signer:       privateKey,
			HeaderKeys:   s.signHeaderKeys,
			QueryMethods: []dkim.QueryMethod{dkim.QueryMethodDNSTXT},
		}

		var err error
		s.signer, err = dkim.NewSigner(&opts)
		if err != nil {
			return nil, err
		}
	}

	// Verify existing signatures
	done := make(chan error, 1)
	pr, pw := io.Pipe()

	s.done = done
	s.pw = pw

	// TODO: limit max. number of signatures
	go func() {
		options := dkim.VerifyOptions{MaxVerifications: maxVerifications}

		var err error
		s.verifs, err = dkim.VerifyWithOptions(pr, &options)
		io.Copy(ioutil.Discard, pr)
		pr.Close()
		done <- err
		close(done)
	}()

	// Process header
	return s.BodyChunk(s.headerBuf.Bytes(), m)
}

func (s *session) BodyChunk(chunk []byte, m *milter.Modifier) (milter.Response, error) {
	if _, err := s.pw.Write(chunk); err != nil {
		return nil, err
	}
	if s.signer != nil {
		if _, err := s.signer.Write(chunk); err != nil {
			return nil, err
		}
	}
	return milter.RespContinue, nil
}

func (s *session) Body(m *milter.Modifier) (milter.Response, error) {
	if err := s.pw.Close(); err != nil {
		return nil, err
	}

	for _, index := range s.authResDelete {
		if err := m.ChangeHeader(index, "Authentication-Results", ""); err != nil {
			return nil, err
		}
	}

	if err := <-s.done; err == dkim.ErrTooManySignatures {
		if verbose {
			log.Printf("Too many signatures in message: %v", err)
		}
		// Ignore the error
	} else if err != nil {
		if verbose {
			log.Printf("DKIM verification failed: %v", err)
		}
		return nil, err
	}

	if s.signer != nil {
		if err := s.signer.Close(); err != nil {
			if verbose {
				log.Printf("DKIM signature failed: %v", err)
			}
			return nil, err
		}

		kv := s.signer.Signature()
		parts := strings.SplitN(kv, ": ", 2)
		if len(parts) != 2 {
			panic("dkim-milter: malformed DKIM-Signature header field")
		}
		k, v := parts[0], strings.TrimSuffix(parts[1], "\r\n")

		if err := m.InsertHeader(0, k, v); err != nil {
			return nil, err
		}
	}

	results := make([]authres.Result, 0, len(s.verifs))

	if len(s.verifs) == 0 && s.signer == nil {
		results = append(results, &authres.DKIMResult{
			Value: authres.ResultNone,
		})
	}

	for _, verif := range s.verifs {
		if verbose {
			if verif.Err != nil {
				log.Printf("DKIM verification failed for %v: %v", verif.Domain, verif.Err)
			} else {
				log.Printf("DKIM verification succeded for %v", verif.Domain)
			}
		}

		var val authres.ResultValue
		if verif.Err == nil {
			val = authres.ResultPass
		} else if dkim.IsPermFail(verif.Err) {
			val = authres.ResultPermError
		} else if dkim.IsTempFail(verif.Err) {
			val = authres.ResultTempError
		} else {
			val = authres.ResultFail
		}

		results = append(results, &authres.DKIMResult{
			Value:      val,
			Domain:     verif.Domain,
			Identifier: verif.Identifier,
		})
	}

	if len(s.verifs) > 0 || s.signer == nil {
		v := authres.Format(identity, results)
		if err := m.InsertHeader(0, "Authentication-Results", v); err != nil {
			return nil, err
		}
	}

	return milter.RespAccept, nil
}

func loadPrivateKey(path string) (openssl.PrivateKey, error) {
	b, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("no PEM data found")
	}

	switch strings.ToUpper(block.Type) {
	case "PRIVATE KEY":
		return openssl.LoadPrivateKeyFromPEM(block.Bytes)
	case "RSA PRIVATE KEY":
		return openssl.LoadPrivateKeyFromPEM(block.Bytes)
	default:
		return nil, fmt.Errorf("unknown private key type: '%v'", block.Type)
	}
}

func main() {
	flag.Parse()

	if identity == "" {
		var err error
		identity, err = os.Hostname()
		if err != nil {
			log.Fatal("Failed to read hostname: ", err)
		}
	}

	if (len(signDomains) > 0 || privateKeyPath != "" || selector != "") && !(len(signDomains) > 0 && privateKeyPath != "" && selector != "") {
		log.Fatal("Domain(s) (-d) and private key (-k) must be both specified")
	}

	for i, pattern := range signDomains {
		if _, err := path.Match(pattern, ""); err != nil {
			log.Fatalf("Malformed domain pattern %q: %v", pattern, err)
		}
		signDomains[i] = strings.ToLower(pattern)
	}

	if privateKeyPath != "" {
		var err error
		privateKey, err = loadPrivateKey(privateKeyPath)
		if err != nil {
			log.Fatalf("Failed to load private key from '%v': %v", privateKeyPath, err)
		}
	}

	parts := strings.SplitN(listenURI, "://", 2)
	if len(parts) != 2 {
		log.Fatal("Invalid listen URI")
	}
	listenNetwork, listenAddr := parts[0], parts[1]

	s := milter.Server{
		NewMilter: func() milter.Milter {
			return &session{}
		},
		Actions:  milter.OptAddHeader | milter.OptChangeHeader,
		Protocol: milter.OptNoConnect | milter.OptNoHelo | milter.OptNoMailFrom | milter.OptNoRcptTo,
	}

	ln, err := net.Listen(listenNetwork, listenAddr)
	if err != nil {
		log.Fatal("Failed to setup listener: ", err)
	}

	// Closing the listener will unlink the unix socket, if any
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		if err := s.Close(); err != nil {
			log.Fatal("Failed to close server: ", err)
		}
	}()

	log.Println("Milter listening at", listenURI)
	if err := s.Serve(ln); err != nil && err != milter.ErrServerClosed {
		log.Fatal("Failed to serve: ", err)
	}
}
