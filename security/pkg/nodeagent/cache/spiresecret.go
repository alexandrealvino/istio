package cache

import (
	"github.com/spiffe/go-spiffe/v2/spiffetls"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"golang.org/x/net/context"
	"google.golang.org/grpc/metadata"
	"sync"
	"time"

	"istio.io/istio/pkg/security"
)

type SpireSecretManager struct {
	mu sync.RWMutex
	// callback function to invoke when detecting secret change.
	notifyCallback func(resourceName string)
}

func NewSpireSecretManager(options *security.Options) (*SpireSecretManager, error) {
	return &SpireSecretManager{}, nil
}

func (s *SpireSecretManager) GenerateSecret(resourceName string) (*security.SecretItem, error) {

	var ctx = metadata.AppendToOutgoingContext(context.Background(), "ClusterID", "Kubernetes")
	listener, err := spiffetls.Listen(ctx, "tcp", "127.0.0.1:8443", tlsconfig.AuthorizeAny())
	println(listener,err,ctx)

	expiry, _ := time.Parse(time.RFC3339, "2022-04-16T19:15:00+00:00")
	created, _ := time.Parse(time.RFC3339, "2021-05-13T14:57:25+00:00")
	return &security.SecretItem{
		ResourceName:     resourceName,
		CertificateChain: []byte(fakeChain),
		PrivateKey:       []byte(fakeKey),
		ExpireTime:       expiry,
		CreatedTime:      created,
	}, nil
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

const fakeKey = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgrndO5zhq7p2oG21v
hkVP1NoZGOfxyc1mqWaWfj0HytShRANCAAQRjzi4JTo6EW3VmX7ZnZf84NITzy6V
h8hl7ApUmYRmOdMtclwQKwZMgSY4VXA7pbZ6OoBqiEYFJIu0D+Q725S5
-----END PRIVATE KEY-----
`

const fakeChain = `-----BEGIN CERTIFICATE-----
MIICtDCCAZygAwIBAgIQOmikcJD3gl5YoX4WrULyFTANBgkqhkiG9w0BAQsFADAe
MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGU1BJRkZFMB4XDTIxMDUxMzE0NTcyNVoX
DTIyMDQxNjE5MTUwMFowHTELMAkGA1UEBhMCVVMxDjAMBgNVBAoTBVNQSVJFMFkw
EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEY84uCU6OhFt1Zl+2Z2X/ODSE88ulYfI
ZewKVJmEZjnTLXJcECsGTIEmOFVwO6W2ejqAaohGBSSLtA/kO9uUuaOBuTCBtjAO
BgNVHQ8BAf8EBAMCA6gwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwG
A1UdEwEB/wQCMAAwHQYDVR0OBBYEFMNhHJpOw0CIP/XpPjU9JutlyOv6MB8GA1Ud
IwQYMBaAFOZutlgp0aVt/8JCnjsd83vuBQC+MDcGA1UdEQQwMC6GLHNwaWZmZTov
L2NsdXN0ZXIubG9jYWwvbnMvZGVmYXVsdC9zYS9kZXRhaWxzMA0GCSqGSIb3DQEB
CwUAA4IBAQDWn+EySVfuUjwsBOPb/4ANmohaOhXxjmLJk2CYQ0DGYHT7cwP5RUx5
3rtst2+o/l5G/LZ5YWzMcKTuhP7yiLCGNISD56gG4FrdXDiCfxoKeklNFcnH4vH+
uaxh0k+cIi1pBk0Mhn+6TlajN5V5FOe4tv6GAlwrRxCm5SheRObyHz6iuKvwVXHr
jYy6py1le3oH//AoYllMJSLFxjEntvCfS1cGO0ihRzWk33invDEmO/1l/sjd5dJv
8hdTKdlDxyNDbZMnWqHz0fJADUd1PkOwtyNgW6K13RppMdaxI1Ou22DmOgHTO3O/
HD8veAf1lbNoZiRw39QR7djqXGswmPA3
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDHDCCAgSgAwIBAgIBADANBgkqhkiG9w0BAQsFADAeMQswCQYDVQQGEwJVUzEP
MA0GA1UEChMGU1BJRkZFMB4XDTIxMDQxNjE5MTQ1MFoXDTIyMDQxNjE5MTUwMFow
HjELMAkGA1UEBhMCVVMxDzANBgNVBAoTBlNQSUZGRTCCASIwDQYJKoZIhvcNAQEB
BQADggEPADCCAQoCggEBAOJU/yDCZKkjF5WlNvrDZLjvWgqL+I1oVBHPrjPVs1dy
ceRaInG2wuPsXDENy0vS6Y2Fek5AJfFfLVVEiThjGyhs5cpPXx9LoOly8l8F5t7v
UObG1VVl5BxIuXBPH+2HjFvy/ezWG3gp+q5AT//Bzt8tS/WdDvvM72gpkEhg8kI3
bLBW0pfwZaMuKDq5UwL4S6Fto3PnX4CSoYNnmjiFwG8KopKvQLQjIHeCQ3queB1b
+4NvbxLi+M6jhfshMvZ752MzTS26PEblGuYTaILNriozc3Bq3tlkJizBTbxJBaUk
ZNbnc4bUBP1GvpTOuhFT5DoeZxvlsugJAD+iMnv4DMkCAwEAAaNlMGMwDgYDVR0P
AQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFOZutlgp0aVt/8JC
njsd83vuBQC+MCEGA1UdEQQaMBiGFnNwaWZmZTovL2NsdXN0ZXIubG9jYWwwDQYJ
KoZIhvcNAQELBQADggEBACEzreItMDpOSnX7u00DBgHLmYzM7qbp1ZiyxBuF9DHo
929r0TSIx7TddZaFMJikWhpBvNHGLfJMuxpuleHoEnNxcuvlMGaBoJ4DIhPZYPuj
fglhUrRbtytLoIMyBIvF7KKBdPH57W48Fu6K2ei9iauokGnIVFAud0zPZOCQEbFn
vY8tj+OrpQUgP6W3WYXlo+O+mvPQ+YnJ9w8QYxixp+IxOR+yGkxieYRfimhs9TqB
q399Zlypv8Z/FXFa6VnALFJp2riq0l6mHuoOo7pCNJtnc3+JI6I987my527Hjv7u
xEpRModcMtkK22NMwgKQlXnDMmzi+T/Uwn9vp/by3Fs=
-----END CERTIFICATE-----
`
