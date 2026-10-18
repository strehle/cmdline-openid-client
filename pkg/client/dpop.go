package client

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// DpopKey holds a private key and its JWK public-key thumbprint for DPoP proof generation.
type DpopKey struct {
	PrivateKey crypto.PrivateKey
	// PublicJwk is the serialized JWK of the public key, embedded in each DPoP proof header.
	PublicJwk map[string]string

	nonceMutex sync.RWMutex
	nonces     map[string]string
}

// NewDpopKeyFromRSA creates a DpopKey from an RSA private key.
func NewDpopKeyFromRSA(priv *rsa.PrivateKey) (*DpopKey, error) {
	if priv == nil {
		return nil, fmt.Errorf("RSA private key is nil")
	}
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
	if priv == nil {
		return nil, fmt.Errorf("EC private key is nil")
	}
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

// JwkThumbprint returns the RFC 7638 SHA-256 thumbprint of the public key,
// base64url-encoded. This is the value to send as dpop_jkt in the authorization request.
func (dk *DpopKey) JwkThumbprint() (string, error) {
	if dk == nil {
		return "", fmt.Errorf("DPoP key is nil")
	}
	// RFC 7638: serialize only the required members, lexicographically sorted, no extra whitespace.
	canonical, err := canonicalJwk(dk.PublicJwk)
	if err != nil {
		return "", fmt.Errorf("marshal JWK thumbprint: %w", err)
	}
	sum := sha256.Sum256(canonical)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// canonicalJwk returns the RFC 7638 canonical JSON for the required JWK members.
// Keys are emitted in lexicographic order with no extra whitespace.
func canonicalJwk(jwk map[string]string) ([]byte, error) {
	var keys []string
	switch jwk["kty"] {
	case "EC":
		keys = []string{"crv", "kty", "x", "y"}
	case "RSA":
		keys = []string{"e", "kty", "n"}
	default:
		return nil, fmt.Errorf("unsupported JWK key type %q", jwk["kty"])
	}
	for _, key := range keys {
		if jwk[key] == "" {
			return nil, fmt.Errorf("missing JWK member %q", key)
		}
	}
	sort.Strings(keys)

	var buf strings.Builder
	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		keyJSON, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		valJSON, err := json.Marshal(jwk[k])
		if err != nil {
			return nil, err
		}
		buf.Write(keyJSON)
		buf.WriteByte(':')
		buf.Write(valJSON)
	}
	buf.WriteByte('}')
	return []byte(buf.String()), nil
}

// CreateDpopProof creates a signed DPoP proof JWT for the given HTTP method and URL.
func CreateDpopProof(method string, htu string, dpopKey *DpopKey) (string, error) {
	if dpopKey == nil {
		return "", fmt.Errorf("DPoP key is nil")
	}
	return createDpopProof(method, htu, dpopKey, dpopKey.nonceFor(htu), "")
}

func createDpopProof(method string, htu string, dpopKey *DpopKey, nonce string, accessToken string) (string, error) {
	if dpopKey == nil {
		return "", fmt.Errorf("DPoP key is nil")
	}
	normalizedHtu, err := normalizeHtu(htu)
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"jti": uuid.New().String(),
		"htm": method,
		"htu": normalizedHtu,
		"iat": now.Unix(),
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		claims["ath"] = base64.RawURLEncoding.EncodeToString(sum[:])
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

func normalizeHtu(rawURL string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("parse DPoP target URI: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("DPoP target URI must be absolute")
	}
	parsed.RawQuery = ""
	parsed.ForceQuery = false
	parsed.Fragment = ""
	parsed.RawFragment = ""
	return parsed.String(), nil
}

func (dk *DpopKey) nonceFor(rawURL string) string {
	if dk == nil {
		return ""
	}
	key := nonceKey(rawURL)
	dk.nonceMutex.RLock()
	defer dk.nonceMutex.RUnlock()
	return dk.nonces[key]
}

func (dk *DpopKey) setNonce(rawURL string, nonce string) {
	if dk == nil || nonce == "" {
		return
	}
	key := nonceKey(rawURL)
	dk.nonceMutex.Lock()
	defer dk.nonceMutex.Unlock()
	if dk.nonces == nil {
		dk.nonces = make(map[string]string)
	}
	dk.nonces[key] = nonce
}

func nonceKey(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return rawURL
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.Host = strings.ToLower(parsed.Host)
	parsed.RawQuery = ""
	parsed.ForceQuery = false
	parsed.Fragment = ""
	parsed.RawFragment = ""
	return parsed.String()
}

// doRequestWithDpop sends req with a fresh DPoP proof. If the server challenges
// with DPoP-Nonce, it stores the nonce and retries the request once.
func doRequestWithDpop(req *http.Request, dpopKey *DpopKey, httpClient http.Client) (*http.Response, error) {
	return doRequestWithDpopAccessToken(req, dpopKey, httpClient, "")
}

func doRequestWithDpopAccessToken(req *http.Request, dpopKey *DpopKey, httpClient http.Client, accessToken string) (*http.Response, error) {
	if dpopKey == nil {
		return httpClient.Do(req)
	}

	currentReq := req
	for attempt := 0; attempt < 2; attempt++ {
		proof, err := createDpopProof(currentReq.Method, currentReq.URL.String(), dpopKey, dpopKey.nonceFor(currentReq.URL.String()), accessToken)
		if err != nil {
			return nil, fmt.Errorf("create DPoP proof: %w", err)
		}
		currentReq.Header.Set("DPoP", proof)

		resp, err := httpClient.Do(currentReq)
		if err != nil {
			return nil, err
		}

		nonce := resp.Header.Get("DPoP-Nonce")
		if nonce != "" {
			dpopKey.setNonce(currentReq.URL.String(), nonce)
		}
		if nonce == "" || resp.StatusCode < 400 || attempt == 1 || !requestCanBeReplayed(req) {
			return resp, nil
		}

		responseBody, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("read DPoP nonce challenge: %w", err)
		}
		var oauthError struct {
			Error string `json:"error"`
		}
		wwwAuthenticate := strings.ToLower(strings.Join(resp.Header.Values("WWW-Authenticate"), ","))
		isNonceChallenge := json.Unmarshal(responseBody, &oauthError) == nil && oauthError.Error == "use_dpop_nonce"
		isNonceChallenge = isNonceChallenge || strings.Contains(wwwAuthenticate, "use_dpop_nonce")
		if !isNonceChallenge {
			resp.Body = io.NopCloser(bytes.NewReader(responseBody))
			return resp, nil
		}

		currentReq = req.Clone(req.Context())
		if req.Body != nil && req.Body != http.NoBody {
			body, err := req.GetBody()
			if err != nil {
				return nil, fmt.Errorf("recreate request body after DPoP nonce challenge: %w", err)
			}
			currentReq.Body = body
		}
	}

	return nil, fmt.Errorf("DPoP request retry exhausted")
}

func requestCanBeReplayed(req *http.Request) bool {
	return req.Body == nil || req.Body == http.NoBody || req.GetBody != nil
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
