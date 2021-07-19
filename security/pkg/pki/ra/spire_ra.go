package ra

import (
	"context"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"io/ioutil"
	"istio.io/istio/security/pkg/pki/util"
	"istio.io/pkg/log"
	"strings"
	"sync"
	"time"
)

// KubernetesRA integrated with an external CA using Kubernetes CSR API
type SpireRA struct {
	//csrInterface  certclient.CertificatesV1beta1Interface
	raOpts        *IstioRAOptions
	keyCertBundle *util.KeyCertBundle
	//CertChain	  []byte
	//KeyPEM		  []byte
	//Root		  []byte
	cancelWatcher     context.CancelFunc
}

const socketPath = "unix:///tmp/agent.sock"

// NewKubernetesRA : Create a RA that interfaces with K8S CSR CA
func NewSpireRA(raOpts *IstioRAOptions) (*SpireRA, error) {
	//keyCertBundle, err := util.NewKeyCertBundleWithRootCertFromFile(raOpts.CaCertFile)
	//keyCertBundle := &SpireRA.GetCAKeyCertBundle()
	//if err != nil {
	//	return nil, raerror.NewError(raerror.CAInitFail, fmt.Errorf("error processing Certificate Bundle for Spire RA"))
	//}
	//keyCertBundle := *util.KeyCertBundle{}
	keyCertBundle := &util.KeyCertBundle{}
	keyCertBundle = FetchAll(keyCertBundle)
	istioRA := &SpireRA{
		//csrInterface:  raOpts.K8sClient,
		raOpts:        raOpts,
		keyCertBundle: keyCertBundle,
	}
	ctx, cancel := context.WithCancel(context.Background())
	istioRA.cancelWatcher = cancel
	go istioRA.startWatchers(ctx)

	return istioRA, nil
}

func (s *SpireRA) FetchIstiodSVID() ([]byte, error) {
	//log.Infof("Fetching cert of istiod from SPIRE")
	var certChain , keyPEM, rootc []byte
	//const socketPath = "unix:///tmp/agent.sock"
	ctx2 := context.Background()
	clt, _ := workloadapi.New(ctx2, workloadapi.WithAddr(socketPath))
	bundle,_:=clt.FetchX509Bundles(ctx2)
	rootc,_ = bundle.Bundles()[0].Marshal()
	svid, _ := clt.FetchX509SVIDs(ctx2)
	//certChain,keyPEM,_=svid[1].Marshal()
	//go s.startWatchers()
	//log.Infof("Use plugged-in cert at ./etc/certs/root-cert.pem")
	//var keyPair tls.Certificate
	for _, k := range svid {
		println(k.ID.String())
		if strings.HasSuffix(k.ID.String(),"istiod") {
			certChain, keyPEM, _ = k.Marshal()
			_ = ioutil.WriteFile("./etc/certs/root-cert.pem",rootc,0600)
			_ = ioutil.WriteFile("./var/run/secrets/istio/certs/root-cert.pem",rootc,0600)
			_ = ioutil.WriteFile("./etc/certs/cert-chain.pem",certChain,0600)
			_ = ioutil.WriteFile("./etc/certs/key.pem",keyPEM,0600)
			//keyPair, _ = tls.X509KeyPair(certChain, keyPEM)
		}
	}
	err := s.keyCertBundle.VerifyAndSetAll(certChain, keyPEM, certChain, rootc)
	if err != nil {
		log.Error("error setting keycertBundle with SPIRE RA")
	}
	return certChain, err
}

// Sign takes a PEM-encoded CSR, subject IDs and lifetime, and returns a certificate signed by k8s CA.
func (s *SpireRA) Sign(csrPEM []byte, subjectIDs []string, requestedLifetime time.Duration, forCA bool) ([]byte, error) {
	log.Infof("Calling FetchIstiodSVID from Sign")
	return s.FetchIstiodSVID()
}

// SignWithCertChain is similar to Sign but returns the leaf cert and the entire cert chain.
func (s *SpireRA) SignWithCertChain(csrPEM []byte, subjectIDs []string, ttl time.Duration, forCA bool) ([]byte, error) {
	log.Infof("Calling FetchIstiodSVID from SignWithCertChain")
	return s.FetchIstiodSVID()
}

// GetCAKeyCertBundle returns the KeyCertBundle for the CA.
func (s *SpireRA) GetCAKeyCertBundle() *util.KeyCertBundle {
	log.Infof("Fetching cert of istiod from SPIRE")
	//go s.startWatchers()
	return s.keyCertBundle
}

// GetCAKeyCertBundle returns the KeyCertBundle for the CA.
func FetchAll(keyCertBundle *util.KeyCertBundle) *util.KeyCertBundle {
	//var keyCertBundle *util.KeyCertBundle

	log.Infof("Fetching all certs of istiod from SPIRE")
	var certChain , keyPEM, rootc []byte
	//const socketPath = "unix:///tmp/agent.sock"
	ctx2 := context.Background()
	clt, _ := workloadapi.New(ctx2, workloadapi.WithAddr(socketPath))
	bundle,_:=clt.FetchX509Bundles(ctx2)
	rootc,_ = bundle.Bundles()[0].Marshal()
	svid, _ := clt.FetchX509SVIDs(ctx2)
	//log.Infof("Use plugged-in cert at ./etc/certs/root-cert.pem")
	for _, k := range svid {
		println(k.ID.String())
		if strings.HasSuffix(k.ID.String(),"istiod") {
			certChain, keyPEM, _ = k.Marshal()
			//println(k.ID.String(), string(certChain),string(keyPEM),string(rootc))
			_ = ioutil.WriteFile("./etc/certs/root-cert.pem",rootc,0600)
			_ = ioutil.WriteFile("./var/run/secrets/istio/certs/root-cert.pem",rootc,0600)
			_ = ioutil.WriteFile("./etc/certs/cert-chain.pem",certChain,0600)
			_ = ioutil.WriteFile("./etc/certs/key.pem",keyPEM,0600)
			err := keyCertBundle.VerifyAndSetAll(certChain, keyPEM, certChain, rootc)
			if err != nil {
				return nil
			}
		}
	}
	//keyCertBundle := &util.KeyCertBundle{
	//	CertBytes:      certChain,
	//	Cert:           nil,
	//	PrivKeyBytes:   []byte{},
	//	PrivKey:        nil,
	//	CertChainBytes: []byte{},
	//	RootCertBytes:  rootc,
	//}
	return keyCertBundle
}



func (s *SpireRA) startWatchers(ctx context.Context) {
	var wg sync.WaitGroup
	//ctx, cancel := context.WithCancel(context.Background())

	// Wait for an os.Interrupt signal
	//go waitForCtrlC(cancel)

	// Creates a new Workload API client, connecting to provided socket path
	// Environment variable `SPIFFE_ENDPOINT_SOCKET` is used as default
	client, err := workloadapi.New(ctx, workloadapi.WithAddr(socketPath))
	if err != nil {
		log.Fatalf("Unable to create workload API client: %v", err)
	}
	defer client.Close()

	wg.Add(1)
	// Start a watcher for X.509 SVID updates
	go func() {
		defer wg.Done()
		err := client.WatchX509Context(ctx, &SpireRA{})
		if err != nil && status.Code(err) != codes.Canceled {
			log.Fatalf("Error watching X.509 context: %v", err)
		}
	}()

	wg.Wait()
}

// x509Watcher is a sample implementation of the workloadapi.X509ContextWatcher interface
type x509Watcher struct{}

// UpdateX509SVIDs is run every time an SVID is updated
func (s *SpireRA) OnX509ContextUpdate(c *workloadapi.X509Context) {
	//for _, svid := range c.SVIDs {
	//	_, _, err := svid.Marshal()
	//	if err != nil {
	//		log.Fatalf("Unable to marshal X.509 SVID: %v", err)
	//	}
	//
	//	//s.istiodCertBundleWatcher.SetAndNotify(key,pem,pem)
	//	//if !bytes.Equal(s.istiodCert, item.RootCert) {
	//	//}
	//
	//	//log.Infof("SVID updated for %q: ", svid.ID.String())
	//}
	//var keyPair tls.Certificate
	for _, k := range c.SVIDs {
		//println(k.ID.String())
		if strings.HasSuffix(k.ID.String(),"istiod") {
			crt, key, _ := k.Marshal()
			log.Infof("SVID updated for %q: ", k.ID.String())
			//keyPair, _ = tls.X509KeyPair(crt, key)
			_ = ioutil.WriteFile("./etc/certs/cert-chain.pem",crt,0600)
			_ = ioutil.WriteFile("./etc/certs/key.pem",key,0600)
			//if s.istiodCert != &keyPair {
			//	log.Infof("SVID updated for istiod")
			//	s.istiodCert = &keyPair
			//}
		}
	}
}

// OnX509ContextWatchError is run when the client runs into an error
func (s *SpireRA) OnX509ContextWatchError(err error) {
	if status.Code(err) != codes.Canceled {
		log.Infof("OnX509ContextWatchError error: %v", err)
	}
}

//// waitForCtrlC waits until an os.Interrupt signal is sent (ctrl + c)
//func waitForCtrlC(cancel context.CancelFunc) {
//	signalCh := make(chan os.Signal, 1)
//	signal.Notify(signalCh, os.Interrupt)
//	<-signalCh
//
//	cancel()
//}