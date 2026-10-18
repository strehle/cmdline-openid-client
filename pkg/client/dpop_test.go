package client

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
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
	proof, err := CreateDpopProof("POST", "https://example.com/token?audience=api#fragment", dk)
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

func TestCreateDpopProofRejectsNilKey(t *testing.T) {
	if _, err := CreateDpopProof("POST", "https://example.com/token", nil); err == nil {
		t.Fatal("expected nil DPoP key to be rejected")
	}
}

func TestDpopNonceChallengeIsRetriedAndStored(t *testing.T) {
	key, err := NewEphemeralDpopKey()
	if err != nil {
		t.Fatal(err)
	}

	requestCount := 0
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		proof := r.Header.Get("DPoP")
		parts := strings.Split(proof, ".")
		if len(parts) != 3 {
			t.Errorf("request %d: expected a DPoP proof", requestCount)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		claims, err := decodeJwtPart(parts[1])
		if err != nil {
			t.Errorf("request %d: decode DPoP claims: %v", requestCount, err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		switch requestCount {
		case 1:
			if claims["nonce"] != nil {
				t.Errorf("first request unexpectedly included nonce %v", claims["nonce"])
			}
			if claims["htu"] != server.URL+"/token" {
				t.Errorf("first request htu = %v", claims["htu"])
			}
			w.Header().Set("DPoP-Nonce", "challenge-nonce")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"error":"use_dpop_nonce"}`)
		case 2:
			if claims["nonce"] != "challenge-nonce" {
				t.Errorf("retried request nonce = %v", claims["nonce"])
			}
			w.Header().Set("DPoP-Nonce", "next-nonce")
			w.WriteHeader(http.StatusOK)
		case 3:
			if claims["nonce"] != "next-nonce" {
				t.Errorf("subsequent request nonce = %v", claims["nonce"])
			}
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected request %d", requestCount)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	req, err := http.NewRequest("POST", server.URL+"/token?audience=api", strings.NewReader("grant_type=client_credentials"))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := doRequestWithDpop(req, key, *server.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("retry status = %d", resp.StatusCode)
	}

	req, err = http.NewRequest("POST", server.URL+"/token?grant=refresh", strings.NewReader("grant_type=refresh_token"))
	if err != nil {
		t.Fatal(err)
	}
	resp, err = doRequestWithDpop(req, key, *server.Client())
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("subsequent status = %d", resp.StatusCode)
	}
	if requestCount != 3 {
		t.Fatalf("request count = %d, want 3", requestCount)
	}
}

func TestDpopResourceRequestIncludesAthAndRetriesNonce(t *testing.T) {
	key, err := NewEphemeralDpopKey()
	if err != nil {
		t.Fatal(err)
	}
	accessToken := "access-token"
	ath := sha256.Sum256([]byte(accessToken))
	expectedAth := base64.RawURLEncoding.EncodeToString(ath[:])

	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if r.Header.Get("Authorization") != "DPoP "+accessToken {
			t.Errorf("authorization = %q", r.Header.Get("Authorization"))
		}
		parts := strings.Split(r.Header.Get("DPoP"), ".")
		if len(parts) != 3 {
			t.Errorf("request %d: expected a DPoP proof", requestCount)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		claims, err := decodeJwtPart(parts[1])
		if err != nil {
			t.Errorf("request %d: decode DPoP claims: %v", requestCount, err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if claims["ath"] != expectedAth {
			t.Errorf("request %d: ath = %v", requestCount, claims["ath"])
		}

		if requestCount == 1 {
			w.Header().Set("DPoP-Nonce", "resource-nonce")
			w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if claims["nonce"] != "resource-nonce" {
			t.Errorf("retried request nonce = %v", claims["nonce"])
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"sub":"user"}`)
	}))
	defer server.Close()

	result, err := fetchUserInfo(accessToken, server.URL+"/userinfo?fields=sub", key, *server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if result["sub"] != "user" {
		t.Fatalf("userinfo sub = %v", result["sub"])
	}
	if requestCount != 2 {
		t.Fatalf("request count = %d, want 2", requestCount)
	}
}

func TestDpopNonceDoesNotRetryDifferentOAuthError(t *testing.T) {
	key, err := NewEphemeralDpopKey()
	if err != nil {
		t.Fatal(err)
	}

	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Header().Set("DPoP-Nonce", "next-nonce")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"invalid_grant"}`)
	}))
	defer server.Close()

	req, err := http.NewRequest("POST", server.URL+"/token", strings.NewReader("grant_type=authorization_code"))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := doRequestWithDpop(req, key, *server.Client())
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if requestCount != 1 {
		t.Fatalf("request count = %d, want 1", requestCount)
	}
	if string(body) != `{"error":"invalid_grant"}` {
		t.Fatalf("response body = %q", body)
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
