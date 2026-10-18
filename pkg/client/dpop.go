package client

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// DpopKey holds a private key and its JWK public-key thumbprint for DPoP proof generation.
type DpopKey struct {
	PrivateKey crypto.PrivateKey
	// PublicJwk is the serialized JWK of the public key, embedded in each DPoP proof header.
	PublicJwk map[string]string
}

// NewDpopKeyFromRSA creates a DpopKey from an RSA private key.
func NewDpopKeyFromRSA(priv *rsa.PrivateKey) (*DpopKey, error) {
	pub := priv.Public().(*rsa.PublicKey)
	nBytes := pub.N.Bytes()
	eBytes := intToBytes(pub.E)
	jwk := map[string]string{
		"kty": "RSA",
		"n":   base64.RawURLEncoding.EncodeToString(nBytes),
		"e":   base64.RawURLEncoding.EncodeToString(eBytes),
	}
	return &DpopKey{PrivateKey: priv, PublicJwk: jwk}, nil
}

// NewDpopKeyFromEC creates a DpopKey from an EC private key (P-256).
func NewDpopKeyFromEC(priv *ecdsa.PrivateKey) (*DpopKey, error) {
	pub := priv.Public().(*ecdsa.PublicKey)
	crv := ""
	switch pub.Curve {
	case elliptic.P256():
		crv = "P-256"
	case elliptic.P384():
		crv = "P-384"
	case elliptic.P521():
		crv = "P-521"
	default:
		return nil, fmt.Errorf("unsupported EC curve for DPoP")
	}
	size := (pub.Curve.Params().BitSize + 7) / 8
	xBytes := padLeft(pub.X.Bytes(), size)
	yBytes := padLeft(pub.Y.Bytes(), size)
	jwk := map[string]string{
		"kty": "EC",
		"crv": crv,
		"x":   base64.RawURLEncoding.EncodeToString(xBytes),
		"y":   base64.RawURLEncoding.EncodeToString(yBytes),
	}
	return &DpopKey{PrivateKey: priv, PublicJwk: jwk}, nil
}

// NewDpopKeyFromX509 creates a DpopKey from an X.509 certificate's private key.
func NewDpopKeyFromX509(cert x509.Certificate, priv crypto.PrivateKey) (*DpopKey, error) {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return NewDpopKeyFromRSA(k)
	case *ecdsa.PrivateKey:
		return NewDpopKeyFromEC(k)
	default:
		return nil, fmt.Errorf("unsupported key type for DPoP: %T", priv)
	}
}

// NewEphemeralDpopKey generates a fresh EC P-256 key pair for DPoP.
// Use this when no client key is available.
func NewEphemeralDpopKey() (*DpopKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate DPoP key: %w", err)
	}
	return NewDpopKeyFromEC(priv)
}

// CreateDpopProof creates a signed DPoP proof JWT for the given HTTP method and URL.
func CreateDpopProof(method string, htu string, dpopKey *DpopKey) (string, error) {
	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"jti": uuid.New().String(),
		"htm": method,
		"htu": htu,
		"iat": now.Unix(),
	}

	var tok *jwt.Token
	switch k := dpopKey.PrivateKey.(type) {
	case *rsa.PrivateKey:
		_ = k
		tok = jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	case *ecdsa.PrivateKey:
		switch k.Curve {
		case elliptic.P256():
			tok = jwt.NewWithClaims(jwt.SigningMethodES256, claims)
		case elliptic.P384():
			tok = jwt.NewWithClaims(jwt.SigningMethodES384, claims)
		case elliptic.P521():
			tok = jwt.NewWithClaims(jwt.SigningMethodES512, claims)
		default:
			return "", fmt.Errorf("unsupported EC curve for DPoP signing")
		}
	default:
		return "", fmt.Errorf("unsupported key type for DPoP: %T", dpopKey.PrivateKey)
	}

	tok.Header["typ"] = "dpop+jwt"
	tok.Header["jwk"] = dpopKey.PublicJwk

	signed, err := tok.SignedString(dpopKey.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("sign DPoP proof: %w", err)
	}
	return signed, nil
}

func intToBytes(n int) []byte {
	if n == 0 {
		return []byte{0}
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte(n & 0xff)}, b...)
		n >>= 8
	}
	return b
}

func padLeft(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}
