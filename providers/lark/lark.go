package lark

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

const (
	appAccessTokenURL string = "https://open.feishu.cn/open-apis/auth/v3/app_access_token/internal/" // get app_access_token

	authURL         string = "https://open.feishu.cn/open-apis/authen/v1/authorize"                 // obtain authorization code
	tokenURL        string = "https://open.feishu.cn/open-apis/authen/v1/oidc/access_token"         // get user_access_token
	refreshTokenURL string = "https://open.feishu.cn/open-apis/authen/v1/oidc/refresh_access_token" // refresh user_access_token
	endpointProfile string = "https://open.feishu.cn/open-apis/authen/v1/user_info"                 // get user info
)

// Lark is the implementation of `goth.Provider` for accessing Lark
type Lark interface {
	GetAppAccessToken() error // get app access token
}

// Provider is the implementation of `goth.Provider` for accessing Lark
type Provider struct {
	ClientKey    string
	Secret       string
	CallbackURL  string
	HTTPClient   *http.Client
	config       *oauth2.Config
	providerName string

	appAccessToken *appAccessToken
}

// New creates a new Lark provider and sets up important connection details.
func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:      clientKey,
		Secret:         secret,
		CallbackURL:    callbackURL,
		providerName:   "lark",
		appAccessToken: &appAccessToken{},
	}
	p.config = newConfig(p, authURL, tokenURL, scopes)
	return p
}

func newConfig(provider *Provider, authURL, tokenURL string, scopes []string) *oauth2.Config {
	c := &oauth2.Config{
		ClientID:     provider.ClientKey,
		ClientSecret: provider.Secret,
		RedirectURL:  provider.CallbackURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  authURL,
			TokenURL: tokenURL,
		},
		Scopes: []string{},
	}

	if len(scopes) > 0 {
		c.Scopes = append(c.Scopes, scopes...)
	}
	return c
}

func (p *Provider) Client() *http.Client {
	return goth.HTTPClientWithFallBack(p.HTTPClient)
}

func (p *Provider) Name() string {
	return p.providerName
}

func (p *Provider) SetName(name string) {
	p.providerName = name
}

// appAccessToken is the local cache of the Lark app access token.
//
// All reads and writes of token/expiresAt go through mu so that a concurrent
// read can never observe a token from before a rotation. inflight records the
// single in-progress fetch (if any); every other caller waits on its done
// channel and reuses that result instead of starting another fetch.
type appAccessToken struct {
	mu        sync.RWMutex
	token     string
	expiresAt time.Time

	inflight *appAccessTokenFlight
}

// appAccessTokenFlight represents one in-progress app access token fetch whose
// result is shared with all callers that arrived while it was running.
type appAccessTokenFlight struct {
	done chan struct{}
	err  error
}

// currentToken returns the cached token under the read lock so that a rotation
// in progress is never observed as a stale value and readers never race with
// the writer.
func (c *appAccessToken) currentToken() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.token
}

// tokenValue ensures a valid app access token is cached and returns it.
// The value is read under the read lock after the fetch (or wait) completes,
// so a caller never picks up the token from before a rotation.
func (p *Provider) tokenValue() (string, error) {
	if err := p.GetAppAccessToken(); err != nil {
		return "", err
	}
	return p.appAccessToken.currentToken(), nil
}

type appAccessTokenReq struct {
	AppID     string `json:"app_id"`     // 自建应用的 app_id
	AppSecret string `json:"app_secret"` // 自建应用的 app_secret
}

type appAccessTokenResp struct {
	Code           int    `json:"code"`             // 错误码
	Msg            string `json:"msg"`              // 错误信息
	AppAccessToken string `json:"app_access_token"` // 用于调用应用级接口的 app_access_token
	Expire         int64  `json:"expire"`           // app_access_token 的过期时间
}

// GetAppAccessToken ensures a valid Lark app access token is cached.
//
// At most one fetch is in flight per Provider at any moment: the first caller
// that finds the cache expired claims the flight and performs the fetch, while
// every other caller waits for that flight to finish and reuses its result.
// The fetch result (success or failure) is never stored in the cache, so a
// failed flight leaves no residue and the next call starts a fresh fetch.
func (p *Provider) GetAppAccessToken() error {
	for {
		cache := p.appAccessToken

		cache.mu.RLock()
		if cache.token != "" && time.Now().Before(cache.expiresAt) {
			cache.mu.RUnlock()
			return nil
		}
		flight := cache.inflight
		cache.mu.RUnlock()

		if flight != nil {
			// Someone else is already fetching; wait for and reuse their result.
			// A failed flight surfaces the same error to every waiter instead of
			// letting them fall back to a stale token, and the flight is always
			// cleared, so this wait is bounded and never reused. On success,
			// re-check the cache under the lock so the reader observes the
			// rotated token rather than the one from before the rotation.
			<-flight.done
			if flight.err != nil {
				return flight.err
			}
			continue
		}

		// Claim the flight. Re-check under the write lock so two callers cannot
		// both start a fetch on the expired-cache path.
		cache.mu.Lock()
		if cache.token != "" && time.Now().Before(cache.expiresAt) {
			cache.mu.Unlock()
			return nil
		}
		if cache.inflight != nil {
			// Lost the claim race; wait on the winner instead.
			cache.mu.Unlock()
			continue
		}
		flight = &appAccessTokenFlight{done: make(chan struct{})}
		cache.inflight = flight
		cache.mu.Unlock()

		return p.fetchAppAccessToken(cache, flight)
	}
}

// fetchAppAccessToken performs the upstream token request for the claimed
// flight, publishes the result to all waiters, and always clears the flight so
// a failure cannot be reused by later callers.
func (p *Provider) fetchAppAccessToken(cache *appAccessToken, flight *appAccessTokenFlight) error {
	// Always publish the outcome and wake waiters, even if the upstream call
	// panics through a custom transport: otherwise waiters would hang forever.
	defer func() {
		cache.mu.Lock()
		cache.inflight = nil
		cache.mu.Unlock()
		close(flight.done)
	}()

	token, expiresAt, err := p.requestAppAccessToken()

	cache.mu.Lock()
	if err == nil {
		// Publish the token and expiry before clearing the flight so a waiter
		// woken by close(done) can never see an expired cache with no flight.
		cache.token = token
		cache.expiresAt = expiresAt
	}
	flight.err = err
	cache.mu.Unlock()
	return err
}

// requestAppAccessToken performs the actual upstream call and returns the
// token together with the moment it expires.
func (p *Provider) requestAppAccessToken() (string, time.Time, error) {
	reqBody, err := json.Marshal(&appAccessTokenReq{
		AppID:     p.ClientKey,
		AppSecret: p.Secret,
	})
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to marshal request body: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, appAccessTokenURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to create app access token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.Client().Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to send app access token request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", time.Time{}, fmt.Errorf("unexpected status code while fetching app access token: %d", resp.StatusCode)
	}

	tokenResp := new(appAccessTokenResp)
	if err = json.NewDecoder(resp.Body).Decode(tokenResp); err != nil {
		return "", time.Time{}, fmt.Errorf("failed to decode app access token response: %w", err)
	}

	if tokenResp.Code != 0 {
		return "", time.Time{}, fmt.Errorf("failed to get app access token: code:%v msg: %s", tokenResp.Code, tokenResp.Msg)
	}

	expirationDuration := time.Duration(tokenResp.Expire) * time.Second
	return tokenResp.AppAccessToken, time.Now().Add(expirationDuration), nil
}

func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	// build lark auth url
	u, err := url.Parse(p.config.AuthCodeURL(state))
	if err != nil {
		panic(err)
	}
	query := u.Query()
	query.Del("response_type")
	query.Del("client_id")
	query.Add("app_id", p.ClientKey)
	u.RawQuery = query.Encode()

	return &Session{
		AuthURL: u.String(),
	}, nil
}

func (p *Provider) UnmarshalSession(data string) (goth.Session, error) {
	s := &Session{}
	err := json.NewDecoder(strings.NewReader(data)).Decode(s)
	return s, err
}

func (p *Provider) Debug(b bool) {
}

type getUserAccessTokenResp struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	Scope            string `json:"scope"`
}

func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	appToken, err := p.tokenValue()
	if err != nil {
		return nil, fmt.Errorf("failed to get app access token: %w", err)
	}
	reqBody := strings.NewReader(`{"grant_type":"refresh_token","refresh_token":"` + refreshToken + `"}`)

	req, err := http.NewRequest(http.MethodPost, refreshTokenURL, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create refresh token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", appToken))

	resp, err := p.Client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send refresh token request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code while refreshing token: %d", resp.StatusCode)
	}

	var oauthResp commResponse[getUserAccessTokenResp]
	err = json.NewDecoder(resp.Body).Decode(&oauthResp)
	if err != nil {
		return nil, fmt.Errorf("failed to decode refreshed token: %w", err)
	}
	if oauthResp.Code != 0 {
		return nil, fmt.Errorf("failed to refresh token: code:%v msg: %s", oauthResp.Code, oauthResp.Msg)
	}

	token := oauth2.Token{
		AccessToken:  oauthResp.Data.AccessToken,
		RefreshToken: oauthResp.Data.RefreshToken,
		Expiry:       time.Now().Add(time.Duration(oauthResp.Data.ExpiresIn) * time.Second),
	}

	return &token, nil
}

func (p *Provider) RefreshTokenAvailable() bool {
	return true
}

type commResponse[T any] struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data T      `json:"data"`
}

type larkUser struct {
	OpenID    string `json:"open_id"`
	UnionID   string `json:"union_id"`
	UserID    string `json:"user_id"`
	Name      string `json:"name"`
	Email     string `json:"enterprise_email"`
	AvatarURL string `json:"avatar_url"`
	Mobile    string `json:"mobile,omitempty"`
}

// FetchUser will go to Lark and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	sess := session.(*Session)
	user := goth.User{
		AccessToken:  sess.AccessToken,
		Provider:     p.Name(),
		RefreshToken: sess.RefreshToken,
		ExpiresAt:    sess.ExpiresAt,
	}
	if user.AccessToken == "" {
		return user, fmt.Errorf("%s cannot get user information without accessToken", p.providerName)
	}

	req, err := http.NewRequest("GET", endpointProfile, nil)
	if err != nil {
		return user, fmt.Errorf("%s failed to create request: %w", p.providerName, err)
	}
	req.Header.Set("Authorization", "Bearer "+user.AccessToken)

	resp, err := p.Client().Do(req)
	if err != nil {
		return user, fmt.Errorf("%s failed to get user information: %w", p.providerName, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return user, fmt.Errorf("%s responded with a %d trying to fetch user information", p.providerName, resp.StatusCode)
	}

	responseBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return user, fmt.Errorf("failed to read response body: %w", err)
	}

	var oauthResp commResponse[larkUser]
	if err = json.Unmarshal(responseBytes, &oauthResp); err != nil {
		return user, fmt.Errorf("failed to decode user info: %w", err)
	}
	if oauthResp.Code != 0 {
		return user, fmt.Errorf("failed to get user info: code:%v msg: %s", oauthResp.Code, oauthResp.Msg)
	}

	u := oauthResp.Data
	user.UserID = u.UserID
	user.Name = u.Name
	user.Email = u.Email
	user.AvatarURL = u.AvatarURL
	user.NickName = u.Name

	if err = json.Unmarshal(responseBytes, &user.RawData); err != nil {
		return user, err
	}
	return user, nil
}
