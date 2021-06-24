package cache

import (
	"github.com/fsnotify/fsnotify"
	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"golang.org/x/net/context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pkg/queue"
	"istio.io/istio/pkg/security"
	"istio.io/pkg/log"
	"os"
	"os/signal"
	"sync"
)

type SpireSecretManager struct {
	mu sync.RWMutex

	// The paths for an existing certificate chain, key and root cert files. Istio agent will
	// use them as the source of secrets if they exist.
	existingCertificateFile model.SdsCertificateConfig

	// configOptions includes all configurable params for the cache.
	configOptions *security.Options

	// callback function to invoke when detecting secret change.
	notifyCallback func(resourceName string)

	// certWatcher watches the certificates for changes and triggers a notification to proxy.
	certWatcher *fsnotify.Watcher
	// certs being watched with file watcher.
	fileCerts map[FileCert]struct{}
	certMutex sync.RWMutex

	// queue maintains all certificate rotation events that need to be triggered when they are about to expire
	queue queue.Delayed
	stop  chan struct{}

	cache spireSecretCache

	trustDomain string
}

type spireSecretCache struct {
	mu       sync.RWMutex
	workload *security.SecretItem
	certRoot []byte
}

const agentSocketPath = "unix:///tmp/agent.sock"

func NewSpireSecretManager(options *security.Options) (*SpireSecretManager, error) {
	ret := &SpireSecretManager{
		queue: queue.NewDelayed(queue.DelayQueueBuffer(0)),
		stop:        make(chan struct{}),
		trustDomain: options.TrustDomain,
	}
	go ret.queue.Run(ret.stop)
	go startWatcher()
	return ret, nil
}

// GetRoot returns cached root cert and cert expiration time. This method is thread safe.
func (s *spireSecretCache) getRoot() (rootCert []byte) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.certRoot
}

// SetRoot sets root cert into cache. This method is thread safe.
func (s *spireSecretCache) setRoot(rootCert []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.certRoot = rootCert
}

func (s *spireSecretCache) getWorkload() *security.SecretItem {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.workload == nil {
		return nil
	}
	return s.workload
}

func (s *spireSecretCache) setWorkload(value *security.SecretItem) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.workload = value
}

func (s *SpireSecretManager) GenerateSecret(resourceName string) (*security.SecretItem, error) {
	log.WithLabels("ResourceName", resourceName).Info("calling GenerateSecret")

	ns, _ := s.getCachedSecret(resourceName)
	println("========NS: %s===========", ns)
	if ns != nil {
		return ns, nil
	}

	ns, _ = s.cache.fetchSecret(resourceName)
	if ns != nil {
		return ns, nil
	}

	return ns, nil
}

func (s *SpireSecretManager) SetUpdateCallback(f func(string)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.notifyCallback = f
}

func (s *SpireSecretManager) UpdateConfigTrustBundle([]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return nil
}

func (s *SpireSecretManager) Close() {
	//nop
}

func (s *SpireSecretManager) callUpdateCallback(resourceName string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.notifyCallback != nil {
		s.notifyCallback(resourceName)
	}
}

//func (s *SpireSecretManager) handleFileWatchSpire() {
//	var timerC <-chan time.Time
//	events := make(map[string]fsnotify.Event)
//
//	for {
//		select {
//		case <-timerC:
//			timerC = nil
//			for resource, event := range events {
//				cacheLog.Infof("file certificate %s changed with event %s, pushing to proxy", resource, event.Op.String())
//				s.certMutex.RLock()
//				resources := s.fileCerts
//				s.certMutex.RUnlock()
//				// Trigger callbacks for all resources referencing this file. This is practically always
//				// a single resource.
//				for k := range resources {
//					if k.Filename == resource {
//						s.CallUpdateCallbackSpire(k.ResourceName)
//					}
//				}
//			}
//			events = make(map[string]fsnotify.Event)
//		case event, ok := <-s.certWatcher.Events:
//			// Channel is closed.
//			if !ok {
//				return
//			}
//			// We only care about updates that change the file content
//			if !(isWrite(event) || isRemove(event) || isCreate(event)) {
//				continue
//			}
//			// Typically inotify notifies about file change after the event i.e. write is complete. It only
//			// does some housekeeping tasks after the event is generated. However in some cases, multiple events
//			// are triggered in quick succession - to handle that case we debounce here.
//			// Use a timer to debounce watch updates
//			cacheLog.Infof("event for file certificate %s : %s, debouncing ", event.Name, event.Op.String())
//			if timerC == nil {
//				timerC = time.After(100 * time.Millisecond) // TODO: Make this configurable if needed.
//				events[event.Name] = event
//			}
//		case err, ok := <-s.certWatcher.Errors:
//			// Channel is closed.
//			if !ok {
//				return
//			}
//			numFileWatcherFailures.Increment()
//			cacheLog.Errorf("certificate watch error: %v", err)
//		}
//	}
//}
//
//func (s *SpireSecretManager) CallUpdateCallbackSpire(resourceName string) {
//	s.certMutex.RLock()
//	defer s.certMutex.RUnlock()
//	if s.notifyCallback != nil {
//		s.notifyCallback(resourceName)
//	}
//}

func (s *spireSecretCache) fetchSecret(resourceName string) (*security.SecretItem, error) {
	var ctx = context.Background()
	client, _ := workloadapi.New(ctx, workloadapi.WithAddr(agentSocketPath))
	defer client.Close()
	svid, _ := client.FetchX509SVID(ctx)

	bundle, _ := client.FetchX509Bundles(ctx)
	fakeRoot, _ := bundle.Bundles()[0].Marshal()
	log.WithLabels("ResourceName", resourceName).Info("calling fetchSecret")
	chain, key, _ := svid.Marshal()
	item := &security.SecretItem{}
	if resourceName == security.RootCertReqResourceName {
		item = &security.SecretItem{
			ResourceName: resourceName,
			RootCert:     fakeRoot,
		}
		s.setRoot(item.RootCert)
	}
	if resourceName == security.WorkloadKeyCertResourceName {
		item = &security.SecretItem{
			ResourceName:     resourceName,
			CertificateChain: chain,
			PrivateKey:       key,
		}
		s.setWorkload(item)
	}
	return item, nil
}

func (s *SpireSecretManager) getCachedSecret(resourceName string) (*security.SecretItem, error) {
	log.WithLabels("ResourceName", resourceName).Info("calling getCachedSecret")
	ret := &security.SecretItem{}
	if resourceName == security.RootCertReqResourceName {
		if c := s.cache.getRoot(); c != nil {
			ret = &security.SecretItem{
				ResourceName: resourceName,
				RootCert:     c,
			}
		} else {
			return nil, nil
		}
	}
	if resourceName == security.WorkloadKeyCertResourceName {
		if item := s.cache.getWorkload(); item != nil {
			ret = &security.SecretItem{
				ResourceName:     resourceName,
				CertificateChain: item.CertificateChain,
				PrivateKey:       item.PrivateKey,
			}
		} else {
			return nil, nil
		}
	}
	return ret, nil
}

// ======================= WATCHER ========================

func startWatcher() {
	ctx, cancel := context.WithCancel(context.Background())

	// Wait for an os.Interrupt signal
	go waitForCtrlC(cancel)

	// Start X.509 and JWT watchers
	startWatchers(ctx)
	println("=========POS WATCHER CALL=========")
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
		err := client.WatchX509Context(ctx, &x509Watcher{})
		if err != nil && status.Code(err) != codes.Canceled {
			log.Fatalf("Error watching X.509 context: %v", err)
		}
	}()

	wg.Add(1)
	// Start a watcher for JWT bundle updates
	go func() {
		defer wg.Done()
		err := client.WatchJWTBundles(ctx, &jwtWatcher{})
		if err != nil && status.Code(err) != codes.Canceled {
			log.Fatalf("Error watching JWT bundles: %v", err)
		}
	}()

	wg.Wait()
}

// x509Watcher is a sample implementation of the workloadapi.X509ContextWatcher interface
type x509Watcher struct{}

// UpdateX509SVIDs is run every time an SVID is updated
func (x509Watcher) OnX509ContextUpdate(c *workloadapi.X509Context) {
	for _, svid := range c.SVIDs {
		pem, _, err := svid.Marshal()
		if err != nil {
			log.Fatalf("Unable to marshal X.509 SVID: %v", err)
		}

		log.Info("SVID updated for %q: \n%s\n", svid.ID, string(pem))
	}
}

// OnX509ContextWatchError is run when the client runs into an error
func (x509Watcher) OnX509ContextWatchError(err error) {
	if status.Code(err) != codes.Canceled {
		log.Info("OnX509ContextWatchError error: %v", err)
	}
}

// jwtWatcher is a sample implementation of the workloadapi.JWTBundleWatcher interface
type jwtWatcher struct{}

// UpdateX509SVIDs is run every time a JWT Bundle is updated
func (jwtWatcher) OnJWTBundlesUpdate(bundleSet *jwtbundle.Set) {
	for _, bundle := range bundleSet.Bundles() {
		jwt, err := bundle.Marshal()
		if err != nil {
			log.Fatalf("Unable to marshal JWT Bundle : %v", err)
		}
		log.Info("jwt bundle updated %q: %s", bundle.TrustDomain(), string(jwt))
	}
}

// OnJWTBundlesWatchError is run when the client runs into an error
func (jwtWatcher) OnJWTBundlesWatchError(err error) {
	if status.Code(err) != codes.Canceled {
		log.Info("OnJWTBundlesWatchError error: %v", err)
	}
}

// waitForCtrlC waits until an os.Interrupt signal is sent (ctrl + c)
func waitForCtrlC(cancel context.CancelFunc) {
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt)
	<-signalCh

	cancel()
}
