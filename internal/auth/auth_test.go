package auth

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMakeJWT(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "secret"
	token, err := MakeJWT(userID, tokenSecret, time.Second*5)
	if err != nil {
		t.Fatalf("Failed to create JWT: %v", err)
	}
	if token == "" {
		t.Fatal("JWT token is empty")
	}

	parsedUserID, err := ValidateJWT(token, tokenSecret)
	if err != nil {
		t.Fatalf("Failed to validate JWT: %v", err)
	}
	if parsedUserID != userID {
		t.Fatalf("Expected user ID %s, got %s", userID, parsedUserID)
	}
	t.Logf("JWT created and validated successfully for user ID: %s", userID)

	time.Sleep(5 * time.Second) // Wait for the token to expire
	parsedUserID, err = ValidateJWT(token, tokenSecret)
	if err == nil {
		t.Fatal("Expected error when validating expired token, got none")
	}
	if parsedUserID != uuid.Nil {
		t.Fatalf("Expected nil user ID for expired token, got %s", parsedUserID)
	}
	t.Logf("Token expired as expected, user ID: %s", parsedUserID)
	t.Log("TestAuthMakeJWT completed successfully")
}

func TestGetBearerToken(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "Bearer mytoken")

	token, err := GetBearerToken(headers)
	if err != nil {
		t.Fatalf("Failed to get bearer token: %v", err)
	}
	if token != "mytoken" {
		t.Fatalf("Expected token 'mytoken', got '%s'", token)
	}

	headers.Set("Authorization", "InvalidToken mytoken")
	_, err = GetBearerToken(headers)
	if err == nil {
		t.Fatal("Expected error when getting bearer token from invalid header, got none")
	}
	t.Logf("Received expected error for invalid token header: %v", err)
}
