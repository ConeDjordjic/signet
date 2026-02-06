package main

import (
	"context"
	"fmt"
	"os"
	"time"

	signet "github.com/ConeDjordjic/signet-go"
)

func main() {
	baseURL := os.Getenv("SIGNET_URL")
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}

	client := signet.NewClient(baseURL, signet.WithTimeout(10*time.Second))
	ctx := context.Background()

	fmt.Println("=== Signet Go Client Example ===")
	fmt.Printf("Connecting to: %s\n\n", baseURL)

	fmt.Print("1. Health check... ")
	if err := client.HealthCheck(ctx); err != nil {
		fmt.Printf("FAILED: %v\n", err)
		fmt.Println("\nMake sure Signet is running at", baseURL)
		os.Exit(1)
	}
	fmt.Println("OK")

	email := fmt.Sprintf("test%d@example.com", time.Now().Unix())
	password := "password123"

	fmt.Printf("\n2. Registering user: %s... ", email)
	authResp, err := client.Register(ctx, signet.RegisterInput{
		Email:    email,
		Password: password,
	})
	if err != nil {
		fmt.Printf("FAILED: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("OK")
	fmt.Printf("   User ID: %s\n", authResp.User.ID)
	fmt.Printf("   Access Token: %s...\n", authResp.AccessToken[:50])

	accessToken := authResp.AccessToken
	refreshToken := authResp.RefreshToken

	fmt.Print("\n3. Verifying token... ")
	verifyResp, err := client.Verify(ctx, accessToken)
	if err != nil {
		fmt.Printf("FAILED: %v\n", err)
		os.Exit(1)
	}
	if !verifyResp.Valid {
		fmt.Println("FAILED: token not valid")
		os.Exit(1)
	}
	fmt.Println("OK")
	fmt.Printf("   Valid: %t\n", verifyResp.Valid)
	fmt.Printf("   User ID: %s\n", *verifyResp.UserID)
	fmt.Printf("   Email: %s\n", *verifyResp.Email)

	fmt.Print("\n4. Getting current user... ")
	userResp, err := client.GetCurrentUser(ctx, accessToken)
	if err != nil {
		fmt.Printf("FAILED: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("OK")
	fmt.Printf("   Email: %s\n", userResp.User.Email)
	fmt.Printf("   Active: %t\n", userResp.User.IsActive)

	fmt.Print("\n5. Refreshing token... ")
	refreshResp, err := client.RefreshToken(ctx, refreshToken)
	if err != nil {
		fmt.Printf("FAILED: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("OK")
	fmt.Printf("   New Access Token: %s...\n", refreshResp.AccessToken[:50])

	accessToken = refreshResp.AccessToken
	refreshToken = refreshResp.RefreshToken

	fmt.Print("\n6. Revoking current access token... ")
	revokeResp, err := client.RevokeToken(ctx, accessToken)
	if err != nil {
		fmt.Printf("FAILED: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("OK")
	fmt.Printf("   Message: %s\n", revokeResp.Message)

	fmt.Print("\n7. Logging out current session... ")
	if err := client.Logout(ctx, refreshToken); err != nil {
		fmt.Printf("FAILED: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("OK")

	fmt.Print("\n8. Logging in again... ")
	authResp, err = client.Login(ctx, signet.LoginInput{
		Email:    email,
		Password: password,
	})
	if err != nil {
		fmt.Printf("FAILED: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("OK")
	accessToken = authResp.AccessToken

	fmt.Print("\n9. Verifying invalid token is rejected... ")
	verifyResp, err = client.Verify(ctx, "invalid.token.here")
	if err != nil {
		fmt.Printf("FAILED: %v\n", err)
		os.Exit(1)
	}
	if verifyResp.Valid {
		fmt.Println("FAILED: invalid token was accepted")
		os.Exit(1)
	}
	fmt.Println("OK (correctly rejected)")

	fmt.Print("\n10. Forgot password flow... ")
	forgotResp, err := client.ForgotPassword(ctx, email)
	if err != nil {
		fmt.Printf("FAILED: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("OK")
	fmt.Printf("   Message: %s\n", forgotResp.Message)
	if forgotResp.ResetToken != nil {
		fmt.Printf("   Reset Token: %s...\n", (*forgotResp.ResetToken)[:20])

		fmt.Print("\n11. Reset password... ")
		resetResp, err := client.ResetPassword(ctx, *forgotResp.ResetToken, "newpassword123")
		if err != nil {
			fmt.Printf("FAILED: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("OK")
		fmt.Printf("    Message: %s\n", resetResp.Message)

		fmt.Print("\n12. Logging in with new password... ")
		authResp, err = client.Login(ctx, signet.LoginInput{
			Email:    email,
			Password: "newpassword123",
		})
		if err != nil {
			fmt.Printf("FAILED: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("OK")
		accessToken = authResp.AccessToken
	}

	fmt.Print("\n13. Deleting account... ")
	if err := client.DeleteAccount(ctx, accessToken); err != nil {
		fmt.Printf("FAILED: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("OK")

	fmt.Print("\n14. Verifying deleted account cannot login... ")
	_, err = client.Login(ctx, signet.LoginInput{
		Email:    email,
		Password: "newpassword123",
	})
	if err == nil {
		fmt.Println("FAILED: login should have failed")
		os.Exit(1)
	}
	fmt.Println("OK (correctly rejected)")

	fmt.Println("\n=== All tests passed! ===")
}
