# goauth

A lightweight Go package providing authentication utilities for API servers, developed following [Boot.dev courses](https://www.boot.dev/) on [HTTP servers in Go](https://www.boot.dev/courses/learn-http-servers-golang).

## Description

The `goauth` package offers essential authentication functions for Go API servers, including:

- Password hashing and verification
- JWT creation and validation
- Refresh token generation
- HTTP request header parsing for Bearer tokens and API keys

## Installation

```bash
go get github.com/benKapl/goauth
```

### Dependencies

This package has the following dependencies:

- github.com/golang-jwt/jwt/v5
- github.com/google/uuid
- golang.org/x/crypto

## Usage

```go
import "github.com/benKapl/goauth"
```

## API Reference

### Password Management

```go
// HashPassword creates a bcrypt hash from a password string
func HashPassword(password string) (string, error)

// CheckPasswordHash compares a password against a hash to check if they match
// Returns an error if they don't
func CheckPasswordHash(password, hash string) error
```

> `tokenSecret` and `issuer` are global variables and should be set as environnement variables

### JWT Handling

```go
// MakeJWT creates a new JWT with the specified user ID, token secret, and expiration duration
func MakeJWT(userID uuid.UUID, tokenSecret, issuer string, expiresIn time.Duration) (string, error)

// ValidateJWT validates a JWT token and returns the user ID if valid
func ValidateJWT(tokenString, tokenSecret, issuer string) (uuid.UUID, error)
```

### Refresh Tokens

```go
// MakeRefreshToken generates a secure random refresh token
func MakeRefreshToken() (string, error)
```

### HTTP Header Parsing

```go
// GetBearerToken extracts a Bearer token from HTTP headers
func GetBearerToken(headers http.Header) (string, error)

// GetApiKey extracts an API key from HTTP headers
func GetApiKey(headers http.Header) (string, error)
```

## Example

```go
package main

import (
    "fmt"
    "net/http"
    "time"

    "github.com/benKapl/goauth"
    "github.com/google/uuid"
)

func main() {
    // Password hashing
    password := "secure_password"
    hashedPassword, _ := goauth.HashPassword(password)

    // Check password
    err := goauth.CheckPasswordHash(password, hashedPassword)
    if err == nil {
        fmt.Println("Password is correct!")
    }

    // Create JWT
    userID := uuid.New()
    tokenSecret := "your-secret-key"
    token, _ := goauth.MakeJWT(userID, tokenSecret, 24*time.Hour)

    // Validate JWT
    validatedUserID, _ := goauth.ValidateJWT(token, tokenSecret)

    // Generate refresh token
    refreshToken, _ := goauth.MakeRefreshToken()

    // Parse request headers in an HTTP handler
    http.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
        token, err := goauth.GetBearerToken(r.Header)
        if err != nil {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        // Validate token and proceed with request handling
    })
}
```
