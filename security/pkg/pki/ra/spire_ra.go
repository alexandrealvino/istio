package ra

import (
	"bytes"
	"context"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"istio.io/istio/pilot/pkg/keycertbundle"
	"istio.io/istio/security/pkg/pki/util"
	"istio.io/pkg/log"
	"strings"
	"sync"
	"time"
)

// SpireRA integrated with an external CA using Spire Workload API
type SpireRA struct {
	sync.Mutex
	raOpts        *IstioRAOptions
	keyCertBundle *util.KeyCertBundle
	certChain	  []byte
	keyPEM		  []byte
	root		  []byte
	cancelWatcher context.CancelFunc
	trustDomain   string
	watcher 	  *keycertbundle.Watcher
}

// NewSpireRA : Create a RA that interfaces with Spire CA
func NewSpireRA(raOpts *IstioRAOptions, watcher *keycertbundle.Watcher) (*SpireRA, error) {

	istioRA := &SpireRA{
		raOpts:        raOpts,
		keyCertBundle: FetchAll(),
		trustDomain:   raOpts.TrustDomain,
		watcher: 	   watcher,
	}

	ctx, cancel := context.WithCancel(context.Background())
	istioRA.cancelWatcher = cancel
	go istioRA.startWatcher(ctx)

	return istioRA, nil
}

// GetCAKeyCertBundle returns the KeyCertBundle for the CA.
func FetchAll() *util.KeyCertBundle {
	keyCertBundle := &util.KeyCertBundle{}
	log.Infof("Fetching all certs of istiod from SPIRE")
	var certChain , keyPEM, rootc []byte
	ctx := context.Background()
	clt, _ := workloadapi.New(ctx)
	defer clt.Close()
	bundle,_:=clt.FetchX509Bundles(ctx)
	rootc,_ = bundle.Bundles()[0].Marshal()
	svid, _ := clt.FetchX509SVIDs(ctx)
	//for _, k := range svid {
		//if strings.HasSuffix(k.ID.String(),"istiod") {
			println(svid[0].ID.String())
			certChain, keyPEM, _ = svid[0].Marshal()
			err := keyCertBundle.VerifyAndSetAll(certChain, keyPEM, certChain, rootc)
			if err != nil {
				return nil
			}
		//}
	//}
	return keyCertBundle
}

func (s *SpireRA) FetchIstiodSVID() ([]byte, error) {
	var certChain , keyPEM, rootc []byte
	ctx := context.Background()
	clt, _ := workloadapi.New(ctx)
	defer clt.Close()

	bundle, err:=clt.FetchX509Bundles(ctx)
	if err != nil {
		return nil, err
	}
	rootc, err = bundle.Bundles()[0].Marshal()
	if err != nil {
		return nil, err
	}
	svid, err := clt.FetchX509SVIDs(ctx)
	if err != nil {
		return nil, err
	}

	for _, k := range svid {
		println(k.ID.String())
		if strings.HasSuffix(k.ID.String(),"istiod") {
			certChain, keyPEM, _ = k.Marshal()
		}
	}
	err = s.keyCertBundle.VerifyAndSetAll(certChain, keyPEM, certChain, rootc)
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
	return s.keyCertBundle
}

func (s *SpireRA) startWatcher(ctx context.Context) {

	// Creates a new Workload API client, connecting to provided socket path
	// Environment variable `SPIFFE_ENDPOINT_SOCKET` is used as default
	client, err := workloadapi.New(ctx)
	if err != nil {
		log.Fatalf("Unable to create workload API client: %v", err)
	}
	defer client.Close()

	err = client.WatchX509Context(ctx, s)
	if err != nil && status.Code(err) != codes.Canceled {
		log.Fatalf("Error watching X.509 context: %v", err)
	}
}

// UpdateX509SVIDs is run every time an SVID is updated
func (s *SpireRA) OnX509ContextUpdate(c *workloadapi.X509Context) {
	s.Lock()
	defer s.Unlock()
	trustDomain, err := spiffeid.TrustDomainFromString(s.raOpts.TrustDomain)

	if err != nil {
		log.Fatalf(err)
		return
	}

	bundle, ok := c.Bundles.Get(trustDomain)
	if !ok {
		log.WithLabels("trust_domain",trustDomain).Fatal("Unable to get trust bundle for trust domain")
		return
	}

	root, err := bundle.Marshal()
	if err != nil {
		log.Fatalf("Unable to marshal trust bundle: %v", err)
		return
	}
	if !bytes.Equal(root,s.root) {
		s.root = root
	}
	//for _, k := range c.SVIDs {
	//	if strings.HasSuffix(k.ID.String(),"istiod") {
			crt, key, _ := c.SVIDs[0].Marshal()
			if !bytes.Equal(s.certChain,crt) {
				s.certChain = crt
				s.keyPEM = key
				err := s.keyCertBundle.VerifyAndSetAll(crt, key, crt, root)
				if err != nil {
					log.Errorf(err)
				}
				s.watcher.SetAndNotify(key, crt, root)
				log.Infof("SVID updated for %q: ", c.SVIDs[0].ID.String())
			}
		//}
	//}
}

// OnX509ContextWatchError is run when the client runs into an error
func (s *SpireRA) OnX509ContextWatchError(err error) {
	if status.Code(err) != codes.Canceled {
		log.Infof("OnX509ContextWatchError error: %v", err)
	}
}
