package client

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// TestJwkThumbprint_EC verifies dpop_jkt computation matches RFC 7638 canonical form.
func TestJwkThumbprint_EC(t *testing.T) {
	// Use the RFC 7638 §3.3 example key (EC P-256).
	dk := &DpopKey{
		PublicJwk: map[string]string{
			"kty": "EC",
			"crv": "P-256",
			"x":   "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
			"y":   "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
		},
	}
	got, err := dk.JwkThumbprint()
	if err != nil {
		t.Fatal(err)
	}
	// Canonical JSON: {"crv":"P-256","kty":"EC","x":"f83...","y":"x_F..."}
	// SHA-256 thumbprint verified independently.
	want := "oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U"
	if got != want {
		t.Errorf("JwkThumbprint() = %q, want %q", got, want)
	}
	// Must be valid base64url without padding
	if _, err := base64.RawURLEncoding.DecodeString(got); err != nil {
		t.Errorf("thumbprint is not valid base64url: %v", err)
	}
}

func TestJwkThumbprint_RSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	dk, err := NewDpopKeyFromRSA(key)
	if err != nil {
		t.Fatal(err)
	}
	jkt, err := dk.JwkThumbprint()
	if err != nil {
		t.Fatal(err)
	}
	if jkt == "" {
		t.Error("expected non-empty thumbprint")
	}
	// Must be valid base64url without padding
	if _, err := base64.RawURLEncoding.DecodeString(jkt); err != nil {
		t.Errorf("thumbprint is not valid base64url: %v", err)
	}
}



func TestCreateDpopProof_RSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	dk, err := NewDpopKeyFromRSA(key)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := CreateDpopProof("POST", "https://example.com/token", dk)
	if err != nil {
		t.Fatal(err)
	}
	assertDpopProof(t, proof, "POST", "https://example.com/token", key)
}

func TestCreateDpopProof_EC(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dk, err := NewDpopKeyFromEC(key)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := CreateDpopProof("POST", "https://example.com/token", dk)
	if err != nil {
		t.Fatal(err)
	}
	assertDpopProof(t, proof, "POST", "https://example.com/token", key)
}

func TestNewEphemeralDpopKey(t *testing.T) {
	dk, err := NewEphemeralDpopKey()
	if err != nil {
		t.Fatal(err)
	}
	if dk.PublicJwk["kty"] != "EC" {
		t.Fatalf("expected kty EC, got %s", dk.PublicJwk["kty"])
	}
	if dk.PublicJwk["crv"] != "P-256" {
		t.Fatalf("expected crv P-256, got %s", dk.PublicJwk["crv"])
	}
	proof, err := CreateDpopProof("GET", "https://example.com/resource", dk)
	if err != nil {
		t.Fatal(err)
	}
	if proof == "" {
		t.Fatal("expected non-empty proof")
	}
}

func assertDpopProof(t *testing.T, proof string, method string, htu string, signingKey interface{}) {
	t.Helper()
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		t.Fatalf("DPoP proof must be a 3-part JWT, got %d parts", len(parts))
	}

	// Decode header
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	headerMap, err := decodeJwtPart(parts[0])
	if err != nil {
		t.Fatalf("parse header: %v", err)
	}
	_ = headerJSON
	if headerMap["typ"] != "dpop+jwt" {
		t.Errorf("expected typ dpop+jwt, got %v", headerMap["typ"])
	}
	if headerMap["jwk"] == nil {
		t.Error("expected jwk in header")
	}

	// Parse and verify claims using jwt library
	var claims jwt.MapClaims
	switch k := signingKey.(type) {
	case *rsa.PrivateKey:
		token, err := jwt.ParseWithClaims(proof, &claims, func(t *jwt.Token) (interface{}, error) {
			return &k.PublicKey, nil
		})
		if err != nil || !token.Valid {
			t.Fatalf("invalid DPoP proof signature: %v", err)
		}
	case *ecdsa.PrivateKey:
		token, err := jwt.ParseWithClaims(proof, &claims, func(t *jwt.Token) (interface{}, error) {
			return &k.PublicKey, nil
		})
		if err != nil || !token.Valid {
			t.Fatalf("invalid DPoP proof signature: %v", err)
		}
	}

	if claims["htm"] != method {
		t.Errorf("expected htm %s, got %v", method, claims["htm"])
	}
	if claims["htu"] != htu {
		t.Errorf("expected htu %s, got %v", htu, claims["htu"])
	}
	if claims["jti"] == nil || claims["jti"] == "" {
		t.Error("expected non-empty jti")
	}
	if claims["iat"] == nil {
		t.Error("expected iat claim")
	}
}
