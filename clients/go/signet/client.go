package signet

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type NaiveTime struct {
	time.Time
}

func (t *NaiveTime) UnmarshalJSON(data []byte) error {
	s := strings.Trim(string(data), "\"")
	if s == "null" || s == "" {
		return nil
	}
	parsed, err := time.Parse("2006-01-02T15:04:05.999999", s)
	if err != nil {
		parsed, err = time.Parse("2006-01-02T15:04:05", s)
		if err != nil {
			return err
		}
	}
	t.Time = parsed.UTC()
	return nil
}

type Client struct {
	baseURL    string
	httpClient *http.Client
}

type ClientOption func(*Client)

func WithHTTPClient(c *http.Client) ClientOption {
	return func(client *Client) {
		client.httpClient = c
	}
}

func WithTimeout(d time.Duration) ClientOption {
	return func(client *Client) {
		client.httpClient.Timeout = d
	}
}

func NewClient(baseURL string, opts ...ClientOption) *Client {
	c := &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

type User struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	FullName  *string   `json:"full_name,omitempty"`
	IsActive  bool      `json:"is_active"`
	CreatedAt NaiveTime `json:"created_at"`
}

type AuthResponse struct {
	User         User   `json:"user"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type RefreshResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type VerifyResponse struct {
	Valid     bool    `json:"valid"`
	UserID    *string `json:"user_id,omitempty"`
	Email     *string `json:"email,omitempty"`
	ProjectID *string `json:"project_id,omitempty"`
	Role      *string `json:"role,omitempty"`
	ExpiresAt *int64  `json:"expires_at,omitempty"`
}

type ProjectContext struct {
	ProjectID string `json:"project_id"`
	Role      string `json:"role"`
}

type CurrentUserResponse struct {
	User           User            `json:"user"`
	ProjectContext *ProjectContext `json:"project_context,omitempty"`
}

type ForgotPasswordResponse struct {
	Message    string  `json:"message"`
	ResetToken *string `json:"reset_token,omitempty"`
}

type ResetPasswordResponse struct {
	Message string `json:"message"`
}

type ErrorResponse struct {
	Error string  `json:"error"`
	Code  *string `json:"code,omitempty"`
}

type APIError struct {
	StatusCode int
	Message    string
	Code       string
}

func (e *APIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("%s (code: %s, status: %d)", e.Message, e.Code, e.StatusCode)
	}
	return fmt.Sprintf("%s (status: %d)", e.Message, e.StatusCode)
}

func (c *Client) doRequest(ctx context.Context, method, path string, body any, result any) error {
	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
		reqBody = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reqBody)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		var errResp ErrorResponse
		if err := json.Unmarshal(respBody, &errResp); err == nil {
			code := ""
			if errResp.Code != nil {
				code = *errResp.Code
			}
			return &APIError{
				StatusCode: resp.StatusCode,
				Message:    errResp.Error,
				Code:       code,
			}
		}
		return &APIError{
			StatusCode: resp.StatusCode,
			Message:    string(respBody),
		}
	}

	if resp.StatusCode == http.StatusNoContent {
		return nil
	}

	if result != nil {
		if err := json.Unmarshal(respBody, result); err != nil {
			return fmt.Errorf("unmarshal response: %w", err)
		}
	}

	return nil
}

func (c *Client) doAuthenticatedRequest(ctx context.Context, method, path, token string, body any, result any) error {
	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
		reqBody = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reqBody)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		var errResp ErrorResponse
		if err := json.Unmarshal(respBody, &errResp); err == nil {
			code := ""
			if errResp.Code != nil {
				code = *errResp.Code
			}
			return &APIError{
				StatusCode: resp.StatusCode,
				Message:    errResp.Error,
				Code:       code,
			}
		}
		return &APIError{
			StatusCode: resp.StatusCode,
			Message:    string(respBody),
		}
	}

	if resp.StatusCode == http.StatusNoContent {
		return nil
	}

	if result != nil {
		if err := json.Unmarshal(respBody, result); err != nil {
			return fmt.Errorf("unmarshal response: %w", err)
		}
	}

	return nil
}

type RegisterInput struct {
	Email    string  `json:"email"`
	Password string  `json:"password"`
	FullName *string `json:"full_name,omitempty"`
}

func (c *Client) Register(ctx context.Context, input RegisterInput) (*AuthResponse, error) {
	var resp AuthResponse
	if err := c.doRequest(ctx, http.MethodPost, "/auth/register", input, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

type LoginInput struct {
	Email     string  `json:"email"`
	Password  string  `json:"password"`
	ProjectID *string `json:"project_id,omitempty"`
}

func (c *Client) Login(ctx context.Context, input LoginInput) (*AuthResponse, error) {
	var resp AuthResponse
	if err := c.doRequest(ctx, http.MethodPost, "/auth/login", input, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) RefreshToken(ctx context.Context, refreshToken string) (*RefreshResponse, error) {
	var resp RefreshResponse
	body := map[string]string{"refresh_token": refreshToken}
	if err := c.doRequest(ctx, http.MethodPost, "/auth/refresh", body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) Logout(ctx context.Context, refreshToken string) error {
	body := map[string]string{"refresh_token": refreshToken}
	return c.doRequest(ctx, http.MethodPost, "/auth/logout", body, nil)
}

func (c *Client) LogoutAll(ctx context.Context, accessToken string) error {
	return c.doAuthenticatedRequest(ctx, http.MethodPost, "/auth/logout-all", accessToken, nil, nil)
}

func (c *Client) Verify(ctx context.Context, token string) (*VerifyResponse, error) {
	var resp VerifyResponse
	body := map[string]string{"token": token}
	if err := c.doRequest(ctx, http.MethodPost, "/auth/verify", body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) GetCurrentUser(ctx context.Context, accessToken string) (*CurrentUserResponse, error) {
	var resp CurrentUserResponse
	if err := c.doAuthenticatedRequest(ctx, http.MethodGet, "/auth/me", accessToken, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) DeleteAccount(ctx context.Context, accessToken string) error {
	return c.doAuthenticatedRequest(ctx, http.MethodDelete, "/auth/account", accessToken, nil, nil)
}

func (c *Client) ForgotPassword(ctx context.Context, email string) (*ForgotPasswordResponse, error) {
	var resp ForgotPasswordResponse
	body := map[string]string{"email": email}
	if err := c.doRequest(ctx, http.MethodPost, "/auth/forgot-password", body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) ResetPassword(ctx context.Context, token, newPassword string) (*ResetPasswordResponse, error) {
	var resp ResetPasswordResponse
	body := map[string]string{"token": token, "password": newPassword}
	if err := c.doRequest(ctx, http.MethodPost, "/auth/reset-password", body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

type RevokeTokenResponse struct {
	Message string `json:"message"`
}

func (c *Client) RevokeToken(ctx context.Context, accessToken string) (*RevokeTokenResponse, error) {
	var resp RevokeTokenResponse
	if err := c.doAuthenticatedRequest(ctx, http.MethodPost, "/auth/revoke", accessToken, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) HealthCheck(ctx context.Context) error {
	return c.doRequest(ctx, http.MethodGet, "/health", nil, nil)
}
