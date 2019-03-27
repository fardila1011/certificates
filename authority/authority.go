package authority

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"sync"
	"time"

	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/crypto/x509util"
)

const legacyAuthority = "step-certificate-authority"

// Authority implements the Certificate Authority internal interface.
type Authority struct {
	config               *Config
	rootX509Certs        []*x509.Certificate
	intermediateIdentity *x509util.Identity
	validateOnce         bool
	certificates         *sync.Map
	ottMap               *sync.Map
	startTime            time.Time
	provisioners         *provisioner.Collection
	db                   db.AuthDB
	// Do not re-initialize
	initOnce bool
}

// New creates and initiates a new Authority type.
func New(config *Config) (*Authority, error) {
	err := config.Validate()
	if err != nil {
		return nil, err
	}

	var a = &Authority{
		config:       config,
		certificates: new(sync.Map),
		ottMap:       new(sync.Map),
		provisioners: provisioner.NewCollection(config.getAudiences()),
	}
	if err := a.init(); err != nil {
		return nil, err
	}
	return a, nil
}

// init performs validation and initializes the fields of an Authority struct.
func (a *Authority) init() error {
	// Check if handler has already been validated/initialized.
	if a.initOnce {
		return nil
	}

	var err error

	// Initialize step-ca Database if defined in configuration.
	// If a.config.DB is nil then a noopDB will be returned.
	if a.db, err = db.New(a.config.DB); err != nil {
		return err
	}

	// Load the root certificates and add them to the certificate store
	a.rootX509Certs = make([]*x509.Certificate, len(a.config.Root))
	for i, path := range a.config.Root {
		crt, err := pemutil.ReadCertificate(path)
		if err != nil {
			return err
		}
		// Add root certificate to the certificate map
		sum := sha256.Sum256(crt.Raw)
		a.certificates.Store(hex.EncodeToString(sum[:]), crt)
		a.rootX509Certs[i] = crt
	}

	// Add federated roots
	for _, path := range a.config.FederatedRoots {
		crt, err := pemutil.ReadCertificate(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(crt.Raw)
		a.certificates.Store(hex.EncodeToString(sum[:]), crt)
	}

	// Decrypt and load intermediate public / private key pair.
	if len(a.config.Password) > 0 {
		a.intermediateIdentity, err = x509util.LoadIdentityFromDisk(
			a.config.IntermediateCert,
			a.config.IntermediateKey,
			pemutil.WithPassword([]byte(a.config.Password)),
		)
		if err != nil {
			return err
		}
	} else {
		a.intermediateIdentity, err = x509util.LoadIdentityFromDisk(a.config.IntermediateCert, a.config.IntermediateKey)
		if err != nil {
			return err
		}
	}

	// Store all the provisioners
	for _, p := range a.config.AuthorityConfig.Provisioners {
		if err := a.provisioners.Store(p); err != nil {
			return err
		}
	}

	// JWT numeric dates are seconds.
	a.startTime = time.Now().Truncate(time.Second)
	// Set flag indicating that initialization has been completed, and should
	// not be repeated.
	a.initOnce = true

	return nil
}
