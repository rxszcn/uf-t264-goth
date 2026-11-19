package lark_test

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/markbates/goth/providers/lark"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type MockedHTTPClient struct {
	mock.Mock
}

func (m *MockedHTTPClient) RoundTrip(req *http.Request) (*http.Response, error) {
	args := m.Mock.Called(req)
	return args.Get(0).(*http.Response), args.Error(1)
}

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := larkProvider()

	a.Equal(p.ClientKey, os.Getenv("LARK_APP_ID"))
	a.Equal(p.Secret, os.Getenv("LARK_APP_SECRET"))
	a.Equal(p.CallbackURL, "/foo")
}

func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := larkProvider()
	session, err := p.BeginAuth("test_state")
	s := session.(*lark.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "https://open.feishu.cn/open-apis/authen/v1/authorize")
	a.Contains(s.AuthURL, "app_id="+os.Getenv("LARK_APP_ID"))
	a.Contains(s.AuthURL, "state=test_state")
	a.Contains(s.AuthURL, fmt.Sprintf("redirect_uri=%s", url.QueryEscape("/foo")))
}

func Test_GetAppAccessToken(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		mockClient := new(MockedHTTPClient)
		p := larkProvider()
		p.HTTPClient = &http.Client{Transport: mockClient}

		mockClient.On("RoundTrip", mock.Anything).Return(&http.Response{
			StatusCode: http.StatusOK,
			Body:       ioutil.NopCloser(strings.NewReader(`{"code":0,"msg":"ok","app_access_token":"test_token","expire":3600}`)),
		}, nil)

		err := p.GetAppAccessToken()
		assert.NoError(t, err)
	})

	t.Run("error on request", func(t *testing.T) {
		mockClient := new(MockedHTTPClient)
		p := larkProvider()
		p.HTTPClient = &http.Client{Transport: mockClient}

		mockClient.On("RoundTrip", mock.Anything).Return(&http.Response{}, errors.New("request error"))

		err := p.GetAppAccessToken()
		assert.Error(t, err)
	})

	t.Run("non-200 status code", func(t *testing.T) {
		mockClient := new(MockedHTTPClient)
		p := larkProvider()
		p.HTTPClient = &http.Client{Transport: mockClient}

		mockClient.On("RoundTrip", mock.Anything).Return(&http.Response{
			StatusCode: http.StatusForbidden,
			Body:       ioutil.NopCloser(strings.NewReader(``)),
		}, nil)

		err := p.GetAppAccessToken()
		assert.Error(t, err)
	})

	t.Run("error on response decode", func(t *testing.T) {
		mockClient := new(MockedHTTPClient)
		p := larkProvider()
		p.HTTPClient = &http.Client{Transport: mockClient}

		mockClient.On("RoundTrip", mock.Anything).Return(&http.Response{
			StatusCode: http.StatusOK,
			Body:       ioutil.NopCloser(strings.NewReader(`not a json`)),
		}, nil)

		err := p.GetAppAccessToken()
		assert.Error(t, err)
	})

	t.Run("error code in response", func(t *testing.T) {
		mockClient := new(MockedHTTPClient)
		p := larkProvider()
		p.HTTPClient = &http.Client{Transport: mockClient}

		mockClient.On("RoundTrip", mock.Anything).Return(&http.Response{
			StatusCode: http.StatusOK,
			Body:       ioutil.NopCloser(strings.NewReader(`{"code":1,"msg":"error message"}`)),
		}, nil)

		err := p.GetAppAccessToken()
		assert.Error(t, err)
	})
}

func Test_FetchUser(t *testing.T) {
	session := &lark.Session{
		AccessToken: "user_access_token",
	}

	t.Run("happy path", func(t *testing.T) {
		mockClient := new(MockedHTTPClient)
		p := larkProvider()
		p.HTTPClient = &http.Client{Transport: mockClient}
		mockClient.On("RoundTrip", mock.Anything).Return(&http.Response{
			StatusCode: http.StatusOK,
			Body:       ioutil.NopCloser(strings.NewReader(`{"code":0,"msg":"ok","data":{"user_id":"test_user_id","name":"test_name","avatar_url":"test_avatar_url","enterprise_email":"test_email"}}`)),
		}, nil)
		user, err := p.FetchUser(session)
		require.NoError(t, err)
		assert.Equal(t, user.UserID, "test_user_id")
		assert.Equal(t, user.Name, "test_name")
		assert.Equal(t, user.AvatarURL, "test_avatar_url")
		assert.Equal(t, user.Email, "test_email")
	})
	t.Run("error on request", func(t *testing.T) {
		mockClient := new(MockedHTTPClient)
		p := larkProvider()
		p.HTTPClient = &http.Client{Transport: mockClient}
		mockClient.On("RoundTrip", mock.Anything).Return(&http.Response{}, errors.New("request error"))
		_, err := p.FetchUser(session)
		require.Error(t, err)
	})
	t.Run("non-200 status code", func(t *testing.T) {
		mockClient := new(MockedHTTPClient)
		p := larkProvider()
		p.HTTPClient = &http.Client{Transport: mockClient}
		mockClient.On("RoundTrip", mock.Anything).Return(&http.Response{
			StatusCode: http.StatusForbidden,
			Body:       ioutil.NopCloser(strings.NewReader(``)),
		}, nil)
		_, err := p.FetchUser(session)
		require.Error(t, err)
	})
	t.Run("error on response decode", func(t *testing.T) {
		mockClient := new(MockedHTTPClient)
		p := larkProvider()
		p.HTTPClient = &http.Client{Transport: mockClient}
		mockClient.On("RoundTrip", mock.Anything).Return(&http.Response{
			StatusCode: http.StatusOK,
			Body:       ioutil.NopCloser(strings.NewReader(`not a json`)),
		}, nil)
		_, err := p.FetchUser(session)
		require.Error(t, err)
	})
	t.Run("error code in response", func(t *testing.T) {
		mockClient := new(MockedHTTPClient)
		p := larkProvider()
		p.HTTPClient = &http.Client{Transport: mockClient}
		mockClient.On("RoundTrip", mock.Anything).Return(&http.Response{
			StatusCode: http.StatusOK,
			Body:       ioutil.NopCloser(strings.NewReader(`{"code":1,"msg":"error message"}`)),
		}, nil)
		_, err := p.FetchUser(session)
		require.Error(t, err)
	})
}

func larkProvider() *lark.Provider {
	return lark.New(os.Getenv("LARK_APP_ID"), os.Getenv("LARK_APP_SECRET"), "/foo")
}

// countingTokenServer is an injected http.RoundTripper that stands in for the
// upstream Lark API. It counts app access token fetches, records the
// Authorization header seen on every non-token request so tests can observe
// which token the read path actually used, and can inject failures or delays.
// Everything is in-process; no external network is touched.
type countingTokenServer struct {
	mu       sync.Mutex
	fetches  int
	authSeen []string
	expire   int64
	delay    time.Duration
	fail     bool
	issued   []string // token issued per fetch; the last value repeats

	// unique makes every fetch issue a distinct token ("token-<n>"); with
	// sequentialDelay each fetch sleeps n*sequentialDelay, so the earliest
	// fetch returns first and the last fetch returns last. Together they make
	// "did a reader observe the token that ended up cached" deterministic.
	unique          bool
	sequentialDelay time.Duration
}

func (s *countingTokenServer) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Path == "/open-apis/auth/v3/app_access_token/internal/" {
		s.mu.Lock()
		s.fetches++
		fetch := s.fetches
		fail, delay, expire := s.fail, s.delay, s.expire
		unique, seqDelay := s.unique, s.sequentialDelay
		token := "token"
		if unique {
			token = fmt.Sprintf("token-%d", fetch)
		} else if len(s.issued) > 0 {
			idx := fetch - 1
			if idx >= len(s.issued) {
				idx = len(s.issued) - 1
			}
			token = s.issued[idx]
		}
		s.mu.Unlock()

		if seqDelay > 0 {
			time.Sleep(time.Duration(fetch) * seqDelay)
		} else if delay > 0 {
			time.Sleep(delay)
		}
		if fail {
			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				Body:       ioutil.NopCloser(strings.NewReader("")),
				Header:     make(http.Header),
			}, nil
		}
		body := fmt.Sprintf(`{"code":0,"msg":"ok","app_access_token":%q,"expire":%d}`, token, expire)
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       ioutil.NopCloser(strings.NewReader(body)),
			Header:     make(http.Header),
		}, nil
	}

	s.mu.Lock()
	s.authSeen = append(s.authSeen, req.Header.Get("Authorization"))
	s.mu.Unlock()
	return &http.Response{
		StatusCode: http.StatusOK,
		Body: ioutil.NopCloser(strings.NewReader(
			`{"code":0,"msg":"ok","data":{"access_token":"user_token","refresh_token":"refresh_token","expires_in":3600,"refresh_expires_in":3600}}`)),
		Header: make(http.Header),
	}, nil
}

func (s *countingTokenServer) setFail(fail bool) {
	s.mu.Lock()
	s.fail = fail
	s.mu.Unlock()
}

func (s *countingTokenServer) setExpire(expire int64) {
	s.mu.Lock()
	s.expire = expire
	s.mu.Unlock()
}

func (s *countingTokenServer) fetchCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fetches
}

func (s *countingTokenServer) previousTokenReads(token string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, h := range s.authSeen {
		if h == "Bearer "+token {
			n++
		}
	}
	return n
}

// staleTokenReads returns the number of read-path requests that carried a token
// other than want. With unique issuance every rotation token has a distinct
// value, so any reader that did not observe the finally-cached token counts as
// stale.
func (s *countingTokenServer) staleTokenReads(want string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, h := range s.authSeen {
		if h != "Bearer "+want {
			n++
		}
	}
	return n
}

// runConcurrently releases n goroutines at the same instant and fails the test
// if they neither all return nor error out within a bound, so a deadlock in the
// coalescing logic shows up as a test failure rather than a hang.
func runConcurrently(t *testing.T, n int, fn func(i int) error) []error {
	t.Helper()
	start := make(chan struct{})
	errs := make([]error, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			<-start
			errs[i] = fn(i)
		}(i)
	}
	close(start)

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent callers did not finish; possible deadlock")
	}
	return errs
}

// Test_GetAppAccessToken_ConcurrentFetchCount asserts that however many callers
// hit an expired cache at the same instant, upstream sees exactly one fetch,
// matching the serial control, and that a failed leading fetch is surfaced to
// every waiter without being cached.
func Test_GetAppAccessToken_ConcurrentFetchCount(t *testing.T) {
	t.Run("serial control", func(t *testing.T) {
		srv := &countingTokenServer{expire: 3600}
		p := larkProvider()
		p.HTTPClient = &http.Client{Transport: srv}

		for i := 0; i < 16; i++ {
			require.NoError(t, p.GetAppAccessToken())
		}
		t.Logf("serial: upstream fetches=%d", srv.fetchCount())
		assert.Equal(t, 1, srv.fetchCount(), "serial calls should fetch once")
	})

	for _, n := range []int{16, 32} {
		t.Run(fmt.Sprintf("concurrent %d", n), func(t *testing.T) {
			srv := &countingTokenServer{expire: 3600, delay: 20 * time.Millisecond}
			p := larkProvider()
			p.HTTPClient = &http.Client{Transport: srv}

			errs := runConcurrently(t, n, func(int) error {
				return p.GetAppAccessToken()
			})
			for _, err := range errs {
				require.NoError(t, err)
			}
			t.Logf("concurrent %d: upstream fetches=%d", n, srv.fetchCount())
			assert.Equal(t, 1, srv.fetchCount(), "concurrent callers must coalesce into one fetch")
		})
	}

	t.Run("leading failure propagates to waiters and is not cached", func(t *testing.T) {
		const n = 16
		srv := &countingTokenServer{expire: 3600, delay: 20 * time.Millisecond, fail: true}
		p := larkProvider()
		p.HTTPClient = &http.Client{Transport: srv}

		errs := runConcurrently(t, n, func(int) error {
			return p.GetAppAccessToken()
		})

		failed := 0
		for _, err := range errs {
			if err != nil {
				failed++
			}
		}
		assert.Equal(t, n, failed, "waiters must receive the leading fetch error, never a stale token")
		t.Logf("leading failure: waiters errored=%d/%d upstream fetches=%d", failed, n, srv.fetchCount())
		assert.Equal(t, 1, srv.fetchCount(), "a failed leading fetch must not spawn extra fetches")

		// After the failure ends, a single call must start a brand new fetch
		// rather than reuse the cached failure.
		srv.setFail(false)
		before := srv.fetchCount()
		require.NoError(t, p.GetAppAccessToken())
		t.Logf("after failure: refetch delta=%d", srv.fetchCount()-before)
		assert.Equal(t, 1, srv.fetchCount()-before, "next call after failure must refetch upstream")
	})
}

// Test_GetAppAccessToken_RotationReadValue asserts that concurrent readers
// racing a token rotation observe the token that ends up cached and never a
// token from a rotation that is being superseded.
//
// The server issues a distinct token per fetch and delays the k-th fetch by
// k*step, so the earliest fetch returns first and the last one returns last and
// wins the cache. Any reader that reports a token other than that final one
// observed a value that was overwritten by a concurrent rotation.
func Test_GetAppAccessToken_RotationReadValue(t *testing.T) {
	const n = 16
	srv := &countingTokenServer{
		expire:          1,
		unique:          true,
		sequentialDelay: 3 * time.Millisecond,
	}
	p := larkProvider()
	p.HTTPClient = &http.Client{Transport: srv}

	// Seed the cache with a short-lived token (fetch #1).
	require.NoError(t, p.GetAppAccessToken())
	require.Equal(t, 1, srv.fetchCount())

	// Let the seeded token expire so the next read path call starts a rotation.
	time.Sleep(1100 * time.Millisecond)
	// The rotated token stays valid for the whole read burst on any machine.
	srv.setExpire(3600)

	// Concurrent readers cross the rotation on the read path.
	errs := runConcurrently(t, n, func(int) error {
		_, err := p.RefreshToken("refresh_token")
		return err
	})
	for _, err := range errs {
		require.NoError(t, err)
	}

	final := fmt.Sprintf("token-%d", srv.fetchCount())
	stale := srv.staleTokenReads(final)
	t.Logf("rotation: upstream fetches=%d final=%s stale-token reads=%d/%d",
		srv.fetchCount(), final, stale, n)

	assert.Equal(t, 2, srv.fetchCount(), "rotation should add exactly one fetch on top of the seed")
	assert.Zero(t, stale, "no reader may observe a superseded token")
	assert.Equal(t, n, srv.previousTokenReads(final), "every reader must observe the final cache value")
}
