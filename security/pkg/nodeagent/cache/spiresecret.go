package cache

import (
	"bytes"
	"fmt"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"golang.org/x/net/context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"istio.io/istio/pkg/security"
	pkiutil "istio.io/istio/security/pkg/pki/util"
	"istio.io/pkg/log"
)

type SpireSecretManager struct {
	sync.RWMutex
	trustDomain       spiffeid.TrustDomain
	configTrustBundle []byte
	secretItem        *security.SecretItem
	notifyCallback    func(resourceName string)
	cancelWatcher     context.CancelFunc
}

func NewSpireSecretManager(opt *security.Options) (*SpireSecretManager, error) {
	td, err := spiffeid.TrustDomainFromString(opt.TrustDomain)
	if err != nil {
		return nil, fmt.Errorf("error trying to parse trust domain %q reason: %v", opt.TrustDomain, err)
	}

	sm := &SpireSecretManager{
		trustDomain: td,
	}

	ctx, cancel := context.WithCancel(context.Background())
	sm.cancelWatcher = cancel
	go sm.watcherTask(ctx)

	return sm, nil
}

func (s *SpireSecretManager) GenerateSecret(resourceName string) (*security.SecretItem, error) {
	s.RLock()
	defer s.RUnlock()

	si := s.secretItem
	if si == nil {
		return nil, fmt.Errorf("secret was not in cache for resource: %v", resourceName)
	}

	if resourceName == security.RootCertReqResourceName {
		rootCertBundle := s.mergeConfigTrustBundle(si.RootCert)
		ns := &security.SecretItem{
			ResourceName: resourceName,
			RootCert:     rootCertBundle,
		}
		cacheLog.WithLabels("ttl", time.Until(si.ExpireTime)).Info("returned workload trust anchor from cache")
		return ns, nil
	}

	ns := &security.SecretItem{
		ResourceName:     resourceName,
		CertificateChain: si.CertificateChain,
		PrivateKey:       si.PrivateKey,
		ExpireTime:       si.ExpireTime,
		CreatedTime:      si.CreatedTime,
	}
	cacheLog.WithLabels("ttl", time.Until(si.ExpireTime)).Info("returned workload certificate from cache")
	return ns, nil
}

func (s *SpireSecretManager) UpdateConfigTrustBundle(trustBundle []byte) error {
	//TODO: remove this log after testing it
	log.WithLabels("UpdateConfigTrustBundle").Info(string(trustBundle))
	s.Lock()
	defer s.Unlock()

	if bytes.Equal(s.configTrustBundle, trustBundle) {
		return nil
	}
	s.configTrustBundle = trustBundle
	s.callUpdateCallback(security.RootCertReqResourceName)
	return nil
}

func (s *SpireSecretManager) Close() {
	if s.cancelWatcher != nil {
		log.Info("Closing secret manager")
		s.cancelWatcher()
	}
}

func (s *SpireSecretManager) SetUpdateCallback(f func(resourceName string)) {
	s.Lock()
	defer s.Unlock()
	s.notifyCallback = f
}

// UpdateX509SVIDs is run every time an SVID is updated or bundle
func (s *SpireSecretManager) OnX509ContextUpdate(c *workloadapi.X509Context) {
	log.Info("Got new identities from SPIRE") //TODO: change this log
	if len(c.SVIDs) < 1 {
		log.Error("Identities were not found on workload API response")
		return
	}
	if len(c.SVIDs[0].Certificates) < 1 {
		log.Error("Leaf certificate was not found on workload API response")
		return
	}
	// lest's assume the first identity is the right one
	svid := c.SVIDs[0]
	workloadChain, workloadKey, err := svid.Marshal()
	if err != nil {
		log.Fatalf("Unable to marshal X.509 SVID: %v", err)
		return
	}

	bundle, ok := c.Bundles.Get(s.trustDomain)
	if !ok {
		log.WithLabels("trust_domain", s.trustDomain).Fatal("Unable to get trust bundle for trust domain")
		return
	}

	root, err := bundle.Marshal()
	if err != nil {
		log.Fatalf("Unable to marshal trust bundle: %v", err)
		return
	}

	certChain := concatCerts([]string{string(workloadChain), string(root)})
	leaf := c.SVIDs[0].Certificates[0]

	item := &security.SecretItem{
		CertificateChain: certChain,
		PrivateKey:       workloadKey,
		RootCert:         root,
		ResourceName:     security.WorkloadKeyCertResourceName,
		CreatedTime:      leaf.NotBefore,
		ExpireTime:       leaf.NotAfter,
	}

	s.Lock()
	defer s.Unlock()

	if s.secretItem == nil || !bytes.Equal(s.secretItem.RootCert, item.RootCert) {
		s.callUpdateCallback(security.RootCertReqResourceName)
	}
	if s.secretItem == nil || !bytes.Equal(s.secretItem.CertificateChain, item.CertificateChain) {
		s.callUpdateCallback(security.WorkloadKeyCertResourceName)
	}
	s.secretItem = item
}

// OnX509ContextWatchError is run when the client runs into an error
func (s *SpireSecretManager) OnX509ContextWatchError(err error) {
	if status.Code(err) != codes.Canceled {
		log.Infof("error while calling workload API: %v", err)
	}
}

func (s *SpireSecretManager) callUpdateCallback(resourceName string) {
	log.WithLabels("resource", resourceName).Info("Identity updated") //TODO: improve message
	if s.notifyCallback != nil {
		s.notifyCallback(resourceName)
	}
}

func (s *SpireSecretManager) mergeConfigTrustBundle(rootCert []byte) []byte {
	return pkiutil.AppendCertByte(s.configTrustBundle, rootCert)
}

func (s *SpireSecretManager) watcherTask(ctx context.Context) {
	// Creates a new Workload API client, connecting to the socket path provided by SPIFFE_ENDPOINT_SOCKET
	client, err := workloadapi.New(ctx)
	if err != nil {
		log.Fatalf("Unable to create workload API client: %v", err)
	}
	defer client.Close()

	err = client.WatchX509Context(ctx, s)
	if err != nil && status.Code(err) != codes.Canceled {
		log.Fatalf("Error watching SPIRE workload API: %v", err)
	}
}
