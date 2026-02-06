# Signet Go Client

A Go client library for the Signet RBAC authentication service.

## Installation

```bash
go get github.com/ConeDjordjic/signet-go
```

## Usage

```go
package main

import (
    "context"
    "fmt"
    "time"

    signet "github.com/ConeDjordjic/signet-go"
)

func main() {
    client := signet.NewClient("http://localhost:8080",
        signet.WithTimeout(10*time.Second),
    )
    ctx := context.Background()

    // Register a new user
    auth, err := client.Register(ctx, signet.RegisterInput{
        Email:    "user@example.com",
        Password: "securepassword123",
    })
    if err != nil {
        panic(err)
    }
    fmt.Printf("User ID: %s\n", auth.User.ID)

    // Verify a token (for backend-to-Signet validation)
    verify, err := client.Verify(ctx, auth.AccessToken)
    if err != nil {
        panic(err)
    }
    if verify.Valid {
        fmt.Printf("Token is valid for user: %s\n", *verify.Email)
    }

    // Get current user info
    user, err := client.GetCurrentUser(ctx, auth.AccessToken)
    if err != nil {
        panic(err)
    }
    fmt.Printf("Current user: %s\n", user.User.Email)

    // Refresh tokens
    refreshed, err := client.RefreshToken(ctx, auth.RefreshToken)
    if err != nil {
        panic(err)
    }
    fmt.Printf("New access token: %s...\n", refreshed.AccessToken[:20])
}
```

## API Reference

### Client Creation

```go
client := signet.NewClient(baseURL string, opts ...ClientOption)
```

Options:
- `signet.WithHTTPClient(c *http.Client)` - Use a custom HTTP client
- `signet.WithTimeout(d time.Duration)` - Set request timeout

### Methods

| Method | Description |
|--------|-------------|
| `Register(ctx, input)` | Register a new user |
| `Login(ctx, input)` | Login with email/password |
| `RefreshToken(ctx, refreshToken)` | Refresh access token |
| `Logout(ctx, refreshToken)` | Logout current session |
| `LogoutAll(ctx, accessToken)` | Logout all sessions |
| `Verify(ctx, token)` | Verify an access token |
| `GetCurrentUser(ctx, accessToken)` | Get authenticated user info |
| `DeleteAccount(ctx, accessToken)` | Delete user account |
| `ForgotPassword(ctx, email)` | Request password reset |
| `ResetPassword(ctx, token, password)` | Reset password with token |
| `HealthCheck(ctx)` | Check service health |

### Error Handling

All methods return an `*APIError` when the server returns an error response:

```go
auth, err := client.Login(ctx, signet.LoginInput{
    Email:    "user@example.com",
    Password: "wrongpassword",
})
if err != nil {
    if apiErr, ok := err.(*signet.APIError); ok {
        fmt.Printf("Status: %d\n", apiErr.StatusCode)
        fmt.Printf("Message: %s\n", apiErr.Message)
        fmt.Printf("Code: %s\n", apiErr.Code)
    }
}
```

## Running the Example

```bash
# Start Signet
cd /path/to/signet
docker compose up -d

# Run the example
cd clients/go/example
go run .
```

The example demonstrates all client features including registration, login, token verification, refresh, password reset, and account deletion.
