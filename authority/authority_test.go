package authority

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/authority/provisioner"
	stepJOSE "github.com/smallstep/cli/jose"
)

func testAuthority(t *testing.T) *Authority {
	maxjwk, err := stepJOSE.ParseKey("testdata/secrets/max_pub.jwk")
	assert.FatalError(t, err)
	clijwk, err := stepJOSE.ParseKey("testdata/secrets/step_cli_key_pub.jwk")
	assert.FatalError(t, err)
	disableRenewal := true
	p := provisioner.List{
		&provisioner.JWK{
			Name: "Max",
			Type: "JWK",
			Key:  maxjwk,
		},
		&provisioner.JWK{
			Name: "step-cli",
			Type: "JWK",
			Key:  clijwk,
		},
		&provisioner.JWK{
			Name: "dev",
			Type: "JWK",
			Key:  maxjwk,
			Claims: &provisioner.Claims{
				DisableRenewal: &disableRenewal,
			},
		},
	}
	c := &Config{
		Address:          "127.0.0.1:443",
		Root:             []string{"testdata/certs/root_ca.crt"},
		IntermediateCert: "testdata/certs/intermediate_ca.crt",
		IntermediateKey:  "testdata/secrets/intermediate_ca_key",
		DNSNames:         []string{"test.ca.smallstep.com"},
		Password:         "pass",
		AuthorityConfig: &AuthConfig{
			Provisioners: p,
		},
	}
	a, err := New(c)
	assert.FatalError(t, err)
	return a
}

func TestAuthorityNew(t *testing.T) {
	type newTest struct {
		config *Config
		err    error
	}
	tests := map[string]func(t *testing.T) *newTest{
		"ok": func(t *testing.T) *newTest {
			c, err := LoadConfiguration("../ca/testdata/ca.json")
			assert.FatalError(t, err)
			return &newTest{
				config: c,
			}
		},
		"fail bad root": func(t *testing.T) *newTest {
			c, err := LoadConfiguration("../ca/testdata/ca.json")
			assert.FatalError(t, err)
			c.Root = []string{"foo"}
			return &newTest{
				config: c,
				err:    errors.New("open foo failed: no such file or directory"),
			}
		},
		"fail bad password": func(t *testing.T) *newTest {
			c, err := LoadConfiguration("../ca/testdata/ca.json")
			assert.FatalError(t, err)
			c.Password = "wrong"
			return &newTest{
				config: c,
				err:    errors.New("error decrypting ../ca/testdata/secrets/intermediate_ca_key: x509: decryption password incorrect"),
			}
		},
		"fail loading CA cert": func(t *testing.T) *newTest {
			c, err := LoadConfiguration("../ca/testdata/ca.json")
			assert.FatalError(t, err)
			c.IntermediateCert = "wrong"
			return &newTest{
				config: c,
				err:    errors.New("open wrong failed: no such file or directory"),
			}
		},
	}

	for name, genTestCase := range tests {
		t.Run(name, func(t *testing.T) {
			tc := genTestCase(t)

			auth, err := New(tc.config)
			if err != nil {
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					sum := sha256.Sum256(auth.rootX509Certs[0].Raw)
					root, ok := auth.certificates.Load(hex.EncodeToString(sum[:]))
					assert.Fatal(t, ok)
					assert.Equals(t, auth.rootX509Certs[0], root)

					assert.True(t, auth.initOnce)
					assert.NotNil(t, auth.intermediateIdentity)
					for _, p := range tc.config.AuthorityConfig.Provisioners {
						_p, ok := auth.provisioners.Load(p.GetID())
						assert.True(t, ok)
						assert.Equals(t, p, _p)
						if kid, encryptedKey, ok := p.GetEncryptedKey(); ok {
							key, ok := auth.provisioners.LoadEncryptedKey(kid)
							assert.True(t, ok)
							assert.Equals(t, encryptedKey, key)
						}
					}
					// sanity check
					_, ok = auth.provisioners.Load("fooo")
					assert.False(t, ok)
				}
			}
		})
	}
}
