package auth

import (
	"encoding/hex"
	"net/http"
	"time"

	"crypto/rand"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(passwordHash), nil
}

// compare the password that the user entered in the HTTP request with the password that is stored in the database.
func CheckPasswordHash(password, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {

	claims := jwt.RegisteredClaims{
		Subject:   userID.String(),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiresIn)),
		Issuer:    "chirpy",
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}

	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(tokenSecret))
}

func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	claims := jwt.RegisteredClaims{}

	_, err := jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(tokenSecret), nil
	})
	if err != nil {
		return uuid.Nil, err
	}

	return uuid.Parse(claims.Subject)
}

func GetBearerToken(headers http.Header) (string, error) {
	httpToken := headers.Get("Authorization")
	if httpToken == "" {
		return "", http.ErrNoCookie
	}
	if len(httpToken) < 7 || httpToken[:7] != "Bearer " {
		return "", http.ErrNoCookie
	}
	return httpToken[7:], nil
}

func MakeRefreshToken() (string, error) {
	key := make([]byte, 32)
	rand.Read(key)

	refresh_token := hex.EncodeToString(key)
	return refresh_token, nil
}

func GetAPIKey(headers http.Header) (string, error) {
	PolkaKey := headers.Get("Authorization")

	if PolkaKey == "" {
		return "", http.ErrNoCookie
	}

	if len(PolkaKey) < 7 || PolkaKey[:7] != "ApiKey " {
		return "", http.ErrNoCookie
	}

	return PolkaKey[7:], nil
}
