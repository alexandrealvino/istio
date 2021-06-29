package cache

import (
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"golang.org/x/net/context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"istio.io/istio/pkg/security"
	"istio.io/pkg/log"
	"strings"
	"sync"
)

type SpireSecretManager struct {
	// configOptions includes all configurable params for the cache.
	configOptions *security.Options

	// callback function to invoke when detecting secret change.
	notifyCallback func(resourceName string)

	// callbackMutex prevents callback concurrency
	callbackMutex sync.RWMutex

	// Cache of workload certificate and root certificate. File based certs are never cached, as
	// lookup is cheap.
	cache SecretCache
}

const agentSocketPath = "unix:///tmp/agent.sock"

func NewSpireSecretManager(options *security.Options) (*SpireSecretManager, error) {
	ret := &SpireSecretManager{}
	go startWatcher()
	return ret, nil
}

func (s *SpireSecretManager) GenerateSecret(resourceName string) (*security.SecretItem, error) {
	log.WithLabels("ResourceName", resourceName).Info("calling GenerateSecret")

	ns, _ := s.getCachedSecret(resourceName)
	if ns != nil {
		return ns, nil
	}

	log.Info("No cert found in cache for ", resourceName, " fetching from SPIRE Workload API")
	ns, _ = s.cache.fetchSecret(resourceName)
	if ns != nil {
		return ns, nil
	}

	return ns, nil
}

func (s *SpireSecretManager) UpdateConfigTrustBundle([]byte) error {
	return nil
}

func (s *SpireSecretManager) Close() {
	//nop
}

func (s *SpireSecretManager) SetUpdateCallback(f func(resourceName string)) {
	s.callbackMutex.Lock()
	defer s.callbackMutex.Unlock()
	s.notifyCallback = f
}

func (s *SpireSecretManager) CallUpdateCallback(resourceName string) {
	s.callbackMutex.Lock()
	defer s.callbackMutex.Unlock()
	if s.notifyCallback != nil {
		s.notifyCallback(resourceName)
	}
}

func (s *SecretCache) fetchSecret(resourceName string) (*security.SecretItem, error) {
	var ctx = context.Background()
	item := &security.SecretItem{}

	client, err := workloadapi.New(ctx, workloadapi.WithAddr(agentSocketPath))
	if err != nil {
		return nil, err
	}
	defer client.Close()

	if resourceName == security.RootCertReqResourceName {
		bundle, err := client.FetchX509Bundles(ctx)
		if err != nil {
			return nil, err
		}
		rootCert, err := bundle.Bundles()[0].Marshal()
		if err != nil {
			return nil, err
		}
		item = &security.SecretItem{
			ResourceName: resourceName,
			RootCert:     rootCert,
		}

		s.SetRoot(item.RootCert)
	}
	if resourceName == security.WorkloadKeyCertResourceName {
		svid, err := client.FetchX509SVID(ctx)
		if err != nil {
			return nil, err
		}
		workloadChain, workloadKey, err := svid.Marshal()
		if err != nil {
			return nil, err
		}
		item = &security.SecretItem{
			ResourceName:     resourceName,
			CertificateChain: workloadChain,
			PrivateKey:       workloadKey,
		}
		s.SetWorkload(item)
	}
	return item, nil
}

func (s *SpireSecretManager) getCachedSecret(resourceName string) (*security.SecretItem, error) {
	ret := &security.SecretItem{}
	if resourceName == security.RootCertReqResourceName {
		if rootCert := s.cache.GetRoot(); rootCert != nil {
			ret = &security.SecretItem{
				ResourceName: resourceName,
				RootCert:     rootCert,
			}
		} else {
			return nil, nil
		}
	}
	if resourceName == security.WorkloadKeyCertResourceName {
		if workloadCert := s.cache.GetWorkload(); workloadCert != nil {
			ret = &security.SecretItem{
				ResourceName:     resourceName,
				CertificateChain: workloadCert.CertificateChain,
				PrivateKey:       workloadCert.PrivateKey,
			}
		} else {
			return nil, nil
		}
	}
	return ret, nil
}

// ======================= WATCHER ========================

func startWatcher() {
	ctx, _ := context.WithCancel(context.Background())

	// Start X.509 watcher
	startWatchers(ctx)
}

func startWatchers(ctx context.Context) {
	var wg sync.WaitGroup

	// Creates a new Workload API client, connecting to provided socket path
	// Environment variable `SPIFFE_ENDPOINT_SOCKET` is used as default
	client, err := workloadapi.New(ctx, workloadapi.WithAddr(agentSocketPath))
	if err != nil {
		log.Fatalf("Unable to create workload API client: %v", err)
	}
	defer client.Close()

	wg.Add(1)
	// Start a watcher for X.509 SVID updates
	go func() {
		defer wg.Done()
		err := client.WatchX509Context(ctx, &SpireSecretManager{})
		if err != nil && status.Code(err) != codes.Canceled {
			log.Fatalf("Error watching X.509 context: %v", err)
		}
	}()

	wg.Wait()
}

// UpdateX509SVIDs is run every time an SVID is updated
func (s *SpireSecretManager) OnX509ContextUpdate(c *workloadapi.X509Context) {
	for _, svid := range c.SVIDs {
		if strings.HasSuffix(svid.ID.String(), security.WorkloadKeyCertResourceName) {
			workloadChain, workloadKey, err := svid.Marshal()
			if err != nil {
				log.Fatalf("Unable to marshal X.509 SVID: %v", err)
			}
			item := &security.SecretItem{
				ResourceName:     security.WorkloadKeyCertResourceName,
				CertificateChain: workloadChain,
				PrivateKey:       workloadKey,
			}
			if s.cache.GetWorkload() != nil {
				s.cache.SetWorkload(item)
				log.Info("SVID updated for: ", svid.ID)
				s.CallUpdateCallback(item.ResourceName)
			} else { s.cache.SetWorkload(item) }
		}
	}
}

// OnX509ContextWatchError is run when the client runs into an error
func (s *SpireSecretManager) OnX509ContextWatchError(err error) {
	if status.Code(err) != codes.Canceled {
		log.Info("OnX509ContextWatchError error: %v", err)
	}
}
