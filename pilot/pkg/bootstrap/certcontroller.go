// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bootstrap

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"io/ioutil"
	"os"
	"os/signal"
	"path"
	"strings"
	"sync"
	"time"

	"istio.io/istio/pilot/pkg/features"
	"istio.io/istio/pilot/pkg/keycertbundle"
	"istio.io/istio/pilot/pkg/serviceregistry/kube/controller"
	"istio.io/istio/security/pkg/k8s/chiron"
	"istio.io/pkg/log"
)

const (
	// defaultCertGracePeriodRatio is the default length of certificate rotation grace period,
	// configured as the ratio of the certificate TTL.
	defaultCertGracePeriodRatio = 0.5

	// defaultMinCertGracePeriod is the default minimum grace period for workload cert rotation.
	defaultMinCertGracePeriod = 10 * time.Minute

	// Default CA certificate path
	// Currently, custom CA path is not supported; no API to get custom CA cert yet.
	defaultCACertPath = "./var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

var (
	KubernetesCAProvider = "kubernetes"
	IstiodCAProvider     = "istiod"
)

// CertController can create certificates signed by K8S server.
func (s *Server) initCertController(args *PilotArgs) error {
	var err error
	var secretNames, dnsNames, namespaces []string

	meshConfig := s.environment.Mesh()
	if meshConfig.GetCertificates() == nil || len(meshConfig.GetCertificates()) == 0 {
		// TODO: if the provider is set to Citadel, use that instead of k8s so the API is still preserved.
		log.Info("No certificates specified, skipping K8S DNS certificate controller")
		return nil
	}

	k8sClient := s.kubeClient
	for _, c := range meshConfig.GetCertificates() {
		name := strings.Join(c.GetDnsNames(), ",")
		if len(name) == 0 { // must have a DNS name
			continue
		}
		if len(c.GetSecretName()) > 0 {
			// Chiron will generate the key and certificate and save them in a secret
			secretNames = append(secretNames, c.GetSecretName())
			dnsNames = append(dnsNames, name)
			namespaces = append(namespaces, args.Namespace)
		}
	}

	// Provision and manage the certificates for non-Pilot services.
	// If services are empty, the certificate controller will do nothing.
	s.certController, err = chiron.NewWebhookController(defaultCertGracePeriodRatio, defaultMinCertGracePeriod,
		k8sClient.CoreV1(), k8sClient.CertificatesV1beta1(),
		defaultCACertPath, secretNames, dnsNames, namespaces)
	if err != nil {
		return fmt.Errorf("failed to create certificate controller: %v", err)
	}
	s.addStartFunc(func(stop <-chan struct{}) error {
		go func() {
			// Run Chiron to manage the lifecycles of certificates
			s.certController.Run(stop)
		}()

		return nil
	})

	return nil
}

// initDNSCerts will create the certificates to be used by Istiod GRPC server and webhooks.
// If the certificate creation fails - for example no support in K8S - returns an error.
// Will use the mesh.yaml DiscoveryAddress to find the default expected address of the control plane,
// with an environment variable allowing override.
//
// Controlled by features.IstiodService env variable, which defines the name of the service to use in the DNS
// cert, or empty for disabling this feature.
//
// TODO: If the discovery address in mesh.yaml is set to port 15012 (XDS-with-DNS-certs) and the name
// matches the k8s namespace, failure to start DNS server is a fatal error.
func (s *Server) initDNSCerts(hostname, customHost, namespace string) error {
	// Name in the Istiod cert - support the old service names as well.
	// validate hostname contains namespace
	parts := strings.Split(hostname, ".")
	hostnamePrefix := parts[0]

	// append custom hostname if there is any
	names := []string{hostname}
	if customHost != "" && customHost != hostname {
		log.Infof("Adding custom hostname %s", customHost)
		names = append(names, customHost)
	}

	// The first is the recommended one, also used by Apiserver for webhooks.
	// add a few known hostnames
	for _, altName := range []string{"istiod", "istiod-remote", "istio-pilot"} {
		name := fmt.Sprintf("%v.%v.svc", altName, namespace)
		if name == hostname || name == customHost {
			continue
		}
		names = append(names, name)
	}

	var certChain, keyPEM, caBundle []byte
	var err error
	if features.PilotCertProvider.Get() == KubernetesCAProvider {
		log.Infof("Generating K8S-signed cert for %v", names)
		certChain, keyPEM, _, err = chiron.GenKeyCertK8sCA(s.kubeClient.CertificatesV1beta1().CertificateSigningRequests(),
			strings.Join(names, ","), hostnamePrefix+".csr.secret", namespace, defaultCACertPath)
		if err != nil {
			return fmt.Errorf("failed genrating ker cert by k8s: %v", err)
		}
		caBundle, err = ioutil.ReadFile(defaultCACertPath)
		if err != nil {
			return fmt.Errorf("failed reading %s: %v", defaultCACertPath, err)
		}
	} else if features.PilotCertProvider.Get() == IstiodCAProvider {
		certChain, keyPEM, err = s.CA.GenKeyCert(names, SelfSignedCACertTTL.Get(), false)
		if err != nil {
			return fmt.Errorf("failed generating istiod key cert %v", err)
		}
		log.Infof("Generating istiod-signed cert for %v:\n %s", names, certChain)
		const socketPath = "unix:///tmp/agent.sock"
		ctx2 := context.Background()
		clt, _ := workloadapi.New(ctx2, workloadapi.WithAddr(socketPath))
		bundle,_:=clt.FetchX509Bundles(ctx2)
		rootc,_ := bundle.Bundles()[0].Marshal()
		svid, _ := clt.FetchX509SVIDs(ctx2)
		for i, k := range svid {
			//println(k.ID.String())
			if strings.HasSuffix(k.ID.String(),"istiod") {
				certChain,keyPEM,_=svid[i].Marshal()
			}
		}
		//certChain,keyPEM,_=svid[0].Marshal()
		go s.startWatchers()
		//caBundle, err = ioutil.ReadFile("./upstream.pem")
		//println("keyPEM ", string(keyPEM), "certChain", string(certChain), "caBundle", string(caBundle))
		signingKeyFile := path.Join(LocalCertDir.Get(), "ca-key.pem")
		// check if signing key file exists the cert dir
		if _, err := os.Stat(signingKeyFile); err != nil {
			log.Infof("No plugged-in cert at %v; self-signed cert is used", signingKeyFile)
			caBundle = s.CA.GetCAKeyCertBundle().GetRootCertPem()
			caBundle = rootc
			s.addStartFunc(func(stop <-chan struct{}) error {
				go func() {
					// regenerate istiod key cert when root cert changes.
					s.watchRootCertAndGenKeyCert(names, stop)
				}()
				return nil
			})
		} else {
			log.Infof("Use plugged-in cert at %v", signingKeyFile)
			caBundle, err = ioutil.ReadFile(path.Join(LocalCertDir.Get(), "root-cert.pem"))
			if err != nil {
				return fmt.Errorf("failed reading %s: %v", path.Join(LocalCertDir.Get(), "root-cert.pem"), err)
			}
		}
	} else if features.PilotCertProvider.Get() == "SPIRE" {
		//certChain, keyPEM, err = s.CA.GenKeyCert(names, SelfSignedCACertTTL.Get(), false)
		if err != nil {
			return fmt.Errorf("failed generating istiod key cert %v", err)
		}
		log.Infof("Fetching cert from SPIRE for %v:\n %s", names, certChain)
		const socketPath = "unix:///tmp/agent.sock"
		ctx2 := context.Background()
		clt, _ := workloadapi.New(ctx2, workloadapi.WithAddr(socketPath))
		bundle,_:=clt.FetchX509Bundles(ctx2)
		_,_ = bundle.Bundles()[0].Marshal()
		svid, _ := clt.FetchX509SVIDs(ctx2)
		certChain,keyPEM,_=svid[0].Marshal()
		go s.startWatchers()
		log.Infof("Use plugged-in cert at ./wl/root-cert.pem")
		caBundle, err = ioutil.ReadFile("./wl/root-cert.pem")
		var keyPair tls.Certificate
		for _, k := range svid {
			println(k.ID.String())
			if strings.HasSuffix(k.ID.String(),"istiod") {
				crt, key, _ := k.Marshal()
				keyPair, _ = tls.X509KeyPair(crt, key)
				s.istiodCert = &keyPair
			}
		}
		//s.istiodCert = &keyPair
		if err != nil {
			return fmt.Errorf("failed reading %s: %v", path.Join(LocalCertDir.Get(), "root-cert.pem"), err)
		}
	} else {
		log.Infof("User specified cert provider: %v", features.PilotCertProvider.Get())
		return nil
	}

	s.istiodCertBundleWatcher.SetAndNotify(keyPEM, certChain, caBundle)
	return nil
}

// TODO(hzxuzonghu): support async notification instead of polling the CA root cert.
func (s *Server) watchRootCertAndGenKeyCert(names []string, stop <-chan struct{}) {
	caBundle := s.CA.GetCAKeyCertBundle().GetRootCertPem()
	for {
		select {
		case <-stop:
			return
		case <-time.After(controller.NamespaceResyncPeriod):
			newRootCert := s.CA.GetCAKeyCertBundle().GetRootCertPem()
			if !bytes.Equal(caBundle, newRootCert) {
				caBundle = newRootCert
				certChain, keyPEM, err := s.CA.GenKeyCert(names, SelfSignedCACertTTL.Get(), false)
				if err != nil {
					log.Errorf("failed generating istiod key cert %v", err)
				} else {
					s.istiodCertBundleWatcher.SetAndNotify(keyPEM, certChain, caBundle)
					log.Infof("regenerated istiod dns cert: %s", certChain)
				}
			}
		}
	}
}

// initCertificateWatches sets up watches for the dns certs.
// 1. plugin cert
// 2. istiod signed certs.
func (s *Server) initCertificateWatches(tlsOptions TLSOptions) error {
	hasPluginCert := hasCustomTLSCerts(tlsOptions)
	// If there is neither plugin cert nor istiod signed cert, return.
	if !hasPluginCert && !features.EnableCAServer {
		return nil
	}
	if hasPluginCert {
		if err := s.istiodCertBundleWatcher.SetFromFilesAndNotify(tlsOptions.KeyFile, tlsOptions.CertFile, tlsOptions.CaCertFile); err != nil {
			return fmt.Errorf("set keyCertBundle failed: %v", err)
		}
		// TODO: Setup watcher for root and restart server if it changes.
		for _, file := range []string{tlsOptions.CertFile, tlsOptions.KeyFile} {
			log.Infof("adding watcher for certificate %s", file)
			if err := s.fileWatcher.Add(file); err != nil {
				return fmt.Errorf("could not watch %v: %v", file, err)
			}
		}
		s.addStartFunc(func(stop <-chan struct{}) error {
			go func() {
				var keyCertTimerC <-chan time.Time
				for {
					select {
					case <-keyCertTimerC:
						keyCertTimerC = nil
						if err := s.istiodCertBundleWatcher.SetFromFilesAndNotify(tlsOptions.KeyFile, tlsOptions.CertFile, tlsOptions.CaCertFile); err != nil {
							log.Errorf("Setting keyCertBundle failed: %v", err)
						}
					case <-s.fileWatcher.Events(tlsOptions.CertFile):
						if keyCertTimerC == nil {
							keyCertTimerC = time.After(watchDebounceDelay)
						}
					case <-s.fileWatcher.Events(tlsOptions.KeyFile):
						if keyCertTimerC == nil {
							keyCertTimerC = time.After(watchDebounceDelay)
						}
					case err := <-s.fileWatcher.Errors(tlsOptions.CertFile):
						log.Errorf("error watching %v: %v", tlsOptions.CertFile, err)
					case err := <-s.fileWatcher.Errors(tlsOptions.KeyFile):
						log.Errorf("error watching %v: %v", tlsOptions.KeyFile, err)
					case <-stop:
						return
					}
				}
			}()
			return nil
		})
	}

	neverStop := make(chan struct{})
	watchCh := s.istiodCertBundleWatcher.AddWatcher()
	if err := s.loadIstiodCert(watchCh, neverStop); err != nil {
		return fmt.Errorf("first time loadIstiodCert failed: %v", err)
	}
	s.addStartFunc(func(stop <-chan struct{}) error {
		go s.reloadIstiodCert(watchCh, stop)
		return nil
	})

	return nil
}

func (s *Server) reloadIstiodCert(watchCh <-chan keycertbundle.KeyCertBundle, stopCh <-chan struct{}) {
	for {
		select {
		case <-stopCh:
			return
		default:
			if err := s.loadIstiodCert(watchCh, stopCh); err != nil {
				log.Errorf("reload istiod cert failed: %v", err)
			}
		}
	}
}

// loadIstiodCert load IstiodCert received from watchCh once
func (s *Server) loadIstiodCert(watchCh <-chan keycertbundle.KeyCertBundle, stopCh <-chan struct{}) error {
	var keyCertBundle keycertbundle.KeyCertBundle
	select {
	case keyCertBundle = <-watchCh:
	case <-stopCh:
		return nil
	}
	keyPair, err := tls.X509KeyPair(keyCertBundle.CertPem, keyCertBundle.KeyPem)

	if err != nil {
		return fmt.Errorf("istiod loading x509 key pairs failed: %v", err)
	}
	for _, c := range keyPair.Certificate {
		x509Cert, err := x509.ParseCertificates(c)
		if err != nil {
			// This can rarely happen, just in case.
			return fmt.Errorf("x509 cert - ParseCertificates() error: %v", err)
		}
		for _, c := range x509Cert {
			log.Infof("x509 cert - Issuer: %q, Subject: %q, SN: %x, NotBefore: %q, NotAfter: %q",
				c.Issuer, c.Subject, c.SerialNumber,
				c.NotBefore.Format(time.RFC3339), c.NotAfter.Format(time.RFC3339))
		}
	}

	log.Info("Istiod certificates are reloaded")
	s.certMu.Lock()
	s.istiodCert = &keyPair
	s.certMu.Unlock()
	return nil
}

const socketPath = "unix:///tmp/agent.sock"

func (s *Server) startWatchers() {
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())

	// Wait for an os.Interrupt signal
	go waitForCtrlC(cancel)

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
		err := client.WatchX509Context(ctx, &Server{})
		if err != nil && status.Code(err) != codes.Canceled {
			log.Fatalf("Error watching X.509 context: %v", err)
		}
	}()

	wg.Wait()
}

// x509Watcher is a sample implementation of the workloadapi.X509ContextWatcher interface
type x509Watcher struct{}

// UpdateX509SVIDs is run every time an SVID is updated
func (s *Server) OnX509ContextUpdate(c *workloadapi.X509Context) {
	for _, svid := range c.SVIDs {
		_, _, err := svid.Marshal()
		if err != nil {
			log.Fatalf("Unable to marshal X.509 SVID: %v", err)
		}

		//s.istiodCertBundleWatcher.SetAndNotify(key,pem,pem)
		//if !bytes.Equal(s.istiodCert, item.RootCert) {
		//}

		log.Infof("SVID updated for %q: ", svid.ID.String())
	}
	var keyPair tls.Certificate
	for _, k := range c.SVIDs {
		//println(k.ID.String())
		if strings.HasSuffix(k.ID.String(),"istiod") {
			crt, key, _ := k.Marshal()
			keyPair, _ = tls.X509KeyPair(crt, key)
			if s.istiodCert != &keyPair {
				log.Infof("SVID updated for istiod")
				s.istiodCert = &keyPair
			}
		}
	}
}

// OnX509ContextWatchError is run when the client runs into an error
func (s *Server) OnX509ContextWatchError(err error) {
	if status.Code(err) != codes.Canceled {
		log.Infof("OnX509ContextWatchError error: %v", err)
	}
}

// waitForCtrlC waits until an os.Interrupt signal is sent (ctrl + c)
func waitForCtrlC(cancel context.CancelFunc) {
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt)
	<-signalCh

	cancel()
}

// concatCerts concatenates PEM certificates, making sure each one starts on a new line
func concatCerts(certsPEM []string) []byte {
	if len(certsPEM) == 0 {
		return []byte{}
	}
	var certChain bytes.Buffer
	for i, c := range certsPEM {
		certChain.WriteString(c)
		if i < len(certsPEM)-1 && !strings.HasSuffix(c, "\n") {
			certChain.WriteString("\n")
		}
	}
	return certChain.Bytes()
}