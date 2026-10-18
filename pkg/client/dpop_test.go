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
