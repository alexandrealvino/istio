package ra

import (
	"context"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"istio.io/istio/pilot/pkg/keycertbundle"
	"istio.io/istio/security/pkg/pki/util"
	"istio.io/pkg/log"
	"sync"
	"time"
)

// SpireRA integrated with an external CA using Spire Workload API
type SpireRA struct {
	sync.Mutex
	raOpts        *IstioRAOptions
	keyCertBundle *util.KeyCertBundle
	istiodCert	  []byte
	cancelWatcher context.CancelFunc
	trustDomain   string
	watcher 	  *keycertbundle.Watcher
}

// NewSpireRA : Create a RA that interfaces with Spire CA
func NewSpireRA(raOpts *IstioRAOptions, watcher *keycertbundle.Watcher) (*SpireRA, error) {

	istioRA := &SpireRA{
		raOpts:        raOpts,
		trustDomain:   raOpts.TrustDomain,
		keyCertBundle: FetchAll(raOpts.TrustDomain),
		watcher: 	   watcher,
	}

	ctx, cancel := context.WithCancel(context.Background())
	istioRA.cancelWatcher = cancel
	go istioRA.startWatcher(ctx)

	return istioRA, nil
}

// FetchAll returns the KeyCertBundle for the RA.
func FetchAll(trustDomain string) *util.KeyCertBundle {
	keyCertBundle := &util.KeyCertBundle{}
	log.Infof("Fetching Identities from Spire Identity Issuer")

	ctx := context.Background()
	clt, err := workloadapi.New(ctx)
	defer clt.Close()
	trustDomain = "example.org"
	td, err := spiffeid.TrustDomainFromString(trustDomain)
	if err != nil{
		log.Errorf("error trying to parse trust domain %q reason: %v", trustDomain, err)
		return nil
	}

	bundles, err := clt.FetchX509Bundles(ctx)
	if err != nil {
		log.Errorf("error trying to fetch bundles: %v", err)
		return nil
	}

	bundle, err := bundles.GetX509BundleForTrustDomain(td)
	if err != nil {
		log.Errorf("error trying to fetch bundle for trust domain %q reason: %v", trustDomain, err)
		return nil
	}

	bundleBytes, err := bundle.Marshal()
	if err != nil {
		log.Errorf("Unable to marshal trust bundle: %v", trustDomain, err)
		return nil
	}

	svid, err := clt.FetchX509SVIDs(ctx)
	if err != nil {
		log.Errorf("error trying to fetch svid's: %v", trustDomain, err)
		return nil
	}

	cert, keyPEM, err := svid[0].Marshal()
	if err != nil {
		log.Errorf("Unable to marshal certificate: %v", err)
		return nil
	}

	err = keyCertBundle.VerifyAndSetAll(cert, keyPEM, cert, bundleBytes)
	if err != nil {
		log.Errorf("Unable to set istiod bundle: %v", err)
		return nil
	}

	return keyCertBundle
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

// OnX509ContextUpdate is run every time an SVID is updated
func (s *SpireRA) OnX509ContextUpdate(c *workloadapi.X509Context) {
	s.Lock()
	defer s.Unlock()
	log.Infof("Got SVID update from Spire")

	s.trustDomain = "example.org"
	trustDomain, err := spiffeid.TrustDomainFromString(s.trustDomain)
	if err != nil{
		log.Errorf("error trying to parse trust domain %q reason: %v", trustDomain, err)
		return
	}

	bundle, ok := c.Bundles.Get(trustDomain)
	if !ok {
		log.Errorf("error trying to fetch bundle for trust domain %q reason: %v", trustDomain, err)
		return
	}

	root, err := bundle.Marshal()
	if err != nil {
		log.Fatalf("Unable to marshal trust bundle: %v", err)
		return
	}

	crt, key, err := c.SVIDs[0].Marshal()
	if err != nil {
		log.Errorf("error trying to fetch svid's: %v", trustDomain, err)
		return
	}

	err = s.keyCertBundle.VerifyAndSetAll(crt, key, crt, root)
	if err != nil {
		log.Errorf("Unable to set istiod bundle: %v", err)
		return
	}

	s.istiodCert = crt
	s.watcher.SetAndNotify(key, crt, root)
}

// OnX509ContextWatchError is run when the client runs into an error
func (s *SpireRA) OnX509ContextWatchError(err error) {
	if status.Code(err) != codes.Canceled {
		log.Infof("OnX509ContextWatchError error: %v", err)
	}
}

// Sign takes a PEM-encoded CSR, subject IDs and lifetime, and returns a certificate signed by k8s CA.
func (s *SpireRA) Sign(csrPEM []byte, subjectIDs []string, requestedLifetime time.Duration, forCA bool) ([]byte, error) {
	log.Infof("Calling FetchIstiodSVID from Sign")
	return s.istiodCert, nil
}

// SignWithCertChain is similar to Sign but returns the leaf cert and the entire cert chain.
func (s *SpireRA) SignWithCertChain(csrPEM []byte, subjectIDs []string, ttl time.Duration, forCA bool) ([]byte, error) {
	log.Infof("Calling FetchIstiodCert from SignWithCertChain")
	return s.istiodCert, nil
}

// GetCAKeyCertBundle returns the KeyCertBundle for the CA.
func (s *SpireRA) GetCAKeyCertBundle() *util.KeyCertBundle {
	log.Infof("Fetching istiod identity and bundle from Spire")
	return s.keyCertBundle
}