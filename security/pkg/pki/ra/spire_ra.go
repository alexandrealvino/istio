package ra

import (
	"context"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"istio.io/istio/security/pkg/k8s/chiron"
	raerror "istio.io/istio/security/pkg/pki/error"
	"istio.io/istio/security/pkg/pki/util"
	"time"
)

// KubernetesRA integrated with an external CA using Kubernetes CSR API
type SpireRA struct {
	//csrInterface  certclient.CertificatesV1beta1Interface
	raOpts        *IstioRAOptions
	keyCertBundle *util.KeyCertBundle
}

// NewKubernetesRA : Create a RA that interfaces with K8S CSR CA
func NewSpireRA(raOpts *IstioRAOptions) (*SpireRA, error) {
	//keyCertBundle, err := util.NewKeyCertBundleWithRootCertFromFile(raOpts.CaCertFile)
	//keyCertBundle, err := ioutil.ReadFile("./bundle.pem")
	//if err != nil {
	//	return nil, raerror.NewError(raerror.CAInitFail, fmt.Errorf("error processing Certificate Bundle for Spire RA"))
	//}


	istioRA := &SpireRA{
		//csrInterface:  raOpts.K8sClient,
		raOpts:        raOpts,
		//keyCertBundle: keyCertBundle{},
	}
	return istioRA, nil
}

func (r *SpireRA) kubernetesSign(csrPEM []byte, csrName string, caCertFile string) ([]byte, error) {
	//csrSpec := &cert.CertificateSigningRequestSpec{
	//	SignerName: &r.raOpts.CaSigner,
	//	Request:    csrPEM,
	//	Groups:     []string{"system:authenticated"},
	//	Usages: []cert.KeyUsage{
	//		cert.UsageDigitalSignature,
	//		cert.UsageKeyEncipherment,
	//		cert.UsageServerAuth,
	//		cert.UsageClientAuth,
	//	},
	//}
	//certChain, _, err := chiron.SignCSRK8s(r.csrInterface.CertificateSigningRequests(), csrName, csrSpec, "", caCertFile, false)
	//if err != nil {
	//	return nil, raerror.NewError(raerror.CertGenError, err)
	//}
	const socketPath = "unix:///tmp/agent.sock"
	ctx2 := context.Background()
	clt, _ := workloadapi.New(ctx2, workloadapi.WithAddr(socketPath))
	bundle,err:=clt.FetchX509Bundles(ctx2)
	if err != nil {
		return nil, raerror.NewError(raerror.CertGenError, err)
		}
	rootc ,_:= bundle.Bundles()[0].Marshal()
	println(string(rootc))
	svid, _ := clt.FetchX509SVIDs(ctx2)
	certChain,_,_:=svid[0].Marshal()
	//caBundle, err = ioutil.ReadFile("./upstream.pem")
	println("svid id ", svid[0].ID.String(), "certChain", string(certChain))
	return certChain, err
}

// Sign takes a PEM-encoded CSR, subject IDs and lifetime, and returns a certificate signed by k8s CA.
func (r *SpireRA) Sign(csrPEM []byte, subjectIDs []string, requestedLifetime time.Duration, forCA bool) ([]byte, error) {
	_, err := preSign(r.raOpts, csrPEM, subjectIDs, requestedLifetime, forCA)
	if err != nil {
		return nil, err
	}
	csrName := chiron.GenCsrName()
	return r.kubernetesSign(csrPEM, csrName, r.raOpts.CaCertFile)
}

// SignWithCertChain is similar to Sign but returns the leaf cert and the entire cert chain.
func (r *SpireRA) SignWithCertChain(csrPEM []byte, subjectIDs []string, ttl time.Duration, forCA bool) ([]byte, error) {
	cert, err := r.Sign(csrPEM, subjectIDs, ttl, forCA)
	if err != nil {
		return nil, err
	}
	chainPem := r.GetCAKeyCertBundle().GetCertChainPem()
	if len(chainPem) > 0 {
		cert = append(cert, chainPem...)
	}
	return cert, nil
}

// GetCAKeyCertBundle returns the KeyCertBundle for the CA.
func (r *SpireRA) GetCAKeyCertBundle() *util.KeyCertBundle {
	return r.keyCertBundle
}
