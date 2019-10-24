package jwt

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/appleboy/gofight/v2"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

type Role int

const (
	OPERATOR Role = 0x1
	ADMIN    Role = 0x1 << 1
)

func (r Role) IsOperator() bool {
	return r&OPERATOR != 0
}

func (r Role) IsAdmin() bool {
	return r&ADMIN != 0
}

type TestUser struct {
	Username string
	Email    string
	Password string // here is just for example
	Role     Role
}

var naiveDatastore = map[string]TestUser{
	"operator": {"operator", "a@a.com", "password1", OPERATOR},
	"admin":    {"admin", "b@b.com", "password2", OPERATOR | ADMIN},
}

func ginHandler(a Auth) *gin.Engine {
	gin.SetMode(gin.TestMode)
	e := gin.New()

	e.POST("/login", a.Authenticate)
	e.POST("/auth/refresh_token", a.RefreshToken)

	hello := func(c *gin.Context) { c.Status(200) }
	e.GET("/operator/hello", operator(a), hello)
	e.GET("/admin/hello", admin(a), hello)
	return e
}

func operator(a Auth) gin.HandlerFunc {
	return a.VerifyPerm(func(claims MapClaims) bool {
		return role(claims).IsOperator()
	})
}

func admin(a Auth) gin.HandlerFunc {
	return a.VerifyPerm(func(claims MapClaims) bool {
		return role(claims).IsAdmin()
	})
}

func role(claims MapClaims) Role {
	return Role(claims["role"].(float64))
}

func NewTestAuth() (Auth, error) {
	return New(Auth{
		SecretKey: []byte("must change here"),
		Authenticator: func(c *gin.Context) (MapClaims, error) {
			var req struct {
				Username string `json:"username"`
				Password string `json:"password"`
			}
			if err := c.ShouldBind(&req); err != nil {
				return nil, ErrorAuthenticationFailed
			}

			u := naiveDatastore[req.Username] // change here fetching from read datastore
			if u.Password != req.Password {
				return nil, ErrorAuthenticationFailed
			}
			return MapClaims{
				"username": u.Username,
				"role":     u.Role,
			}, nil
		},
		UserFetcher: func(c *gin.Context, claims MapClaims) (interface{}, error) {
			username, ok := claims["username"].(string)
			if !ok {
				return nil, errors.New("data inconsistency occurred")
			}
			u, ok := naiveDatastore[username]
			if !ok {
				return nil, errors.New("user not found")
			}
			return u, nil
		},
	})
}

func NewJWTToken() (string, error) {
	auth, err := NewTestAuth()
	if err != nil {
		return "", err
	}

	handler := ginHandler(auth)
	r := gofight.New()

	var token string

	r.POST("/login").
		SetJSON(gofight.D{
			"username": "operator",
			"password": "password1",
		}).
		Run(handler, func(res gofight.HTTPResponse, req gofight.HTTPRequest) {
			token, err = auth.authToken(res.HeaderMap)
		})
	return token, err
}

func TestIntegrated(t *testing.T) {
	jwt.TimeFunc = time.Now

	assert := assert.New(t)
	auth, err := NewTestAuth()
	assert.NoError(err)

	handler := ginHandler(auth)
	r := gofight.New()

	var (
		opeTokenBeforeRefresh string
		opeTokenAfterRefresh  string
	)

	r.POST("/login").
		SetJSON(gofight.D{
			"username": "operator",
			"password": "password1",
		}).
		Run(handler, func(res gofight.HTTPResponse, req gofight.HTTPRequest) {
			opeTokenBeforeRefresh, err = auth.authToken(res.HeaderMap)
			assert.NotEmpty(opeTokenBeforeRefresh)
			assert.NoError(err)
			assert.Equal(http.StatusOK, res.Code)
		})

	// time leap to 20 mins later
	auth.nowFunc = func() time.Time { return time.Now().Add(20 * time.Minute) }
	jwt.TimeFunc = auth.nowFunc
	handler = ginHandler(auth)

	r.POST("/auth/refresh_token").
		SetHeader(gofight.H{
			authorizationHeaderKey: authorizationHeaderPrefix + opeTokenBeforeRefresh,
		}).
		Run(handler, func(res gofight.HTTPResponse, req gofight.HTTPRequest) {
			if assert.Equal(http.StatusOK, res.Code) {
				opeTokenAfterRefresh, err = auth.authToken(res.HeaderMap)
				assert.NotEmpty(opeTokenAfterRefresh)
				assert.NoError(err)

				before, err := auth._parseToken(opeTokenBeforeRefresh)
				assert.NoError(err)
				after, err := auth._parseToken(opeTokenAfterRefresh)
				assert.NoError(err)

				// check if exp was updated
				beforeExp := before.Claims.(MapClaims)["exp"].(float64)
				afterExp := after.Claims.(MapClaims)["exp"].(float64)
				assert.True(beforeExp < afterExp, fmt.Sprintf("before=%f: after=%f", beforeExp, afterExp))
			}
		})

	// operator is allowed to access to operator path.
	r.GET("/operator/hello").
		SetHeader(gofight.H{
			authorizationHeaderKey: authorizationHeaderPrefix + opeTokenAfterRefresh,
		}).
		Run(handler, func(res gofight.HTTPResponse, req gofight.HTTPRequest) {
			assert.Equal(http.StatusOK, res.Code)
		})

	// operator isn't allowed to access to operator path.
	r.GET("/admin/hello").
		SetHeader(gofight.H{
			authorizationHeaderKey: authorizationHeaderPrefix + opeTokenAfterRefresh,
		}).
		Run(handler, func(res gofight.HTTPResponse, req gofight.HTTPRequest) {
			assert.Equal(http.StatusForbidden, res.Code)
		})

	// time leap to 2 hour later
	auth.nowFunc = func() time.Time { return time.Now().Add(2 * time.Hour) }
	jwt.TimeFunc = auth.nowFunc
	handler = ginHandler(auth)

	r.GET("/operator/hello").
		SetHeader(gofight.H{
			authorizationHeaderKey: authorizationHeaderPrefix + opeTokenAfterRefresh,
		}).
		Run(handler, func(res gofight.HTTPResponse, req gofight.HTTPRequest) {
			assert.Equal(http.StatusUnauthorized, res.Code)
		})

	var adminToken string
	r.POST("/login").
		SetJSON(gofight.D{
			"username": "admin",
			"password": "password2",
		}).
		Run(handler, func(res gofight.HTTPResponse, req gofight.HTTPRequest) {
			adminToken, err = auth.authToken(res.HeaderMap)
			assert.NotEmpty(adminToken)
			assert.NoError(err)
			assert.Equal(http.StatusOK, res.Code)
		})

	// admin is allowed to access to operator path.
	r.GET("/operator/hello").
		SetHeader(gofight.H{
			authorizationHeaderKey: authorizationHeaderPrefix + adminToken,
		}).
		Run(handler, func(res gofight.HTTPResponse, req gofight.HTTPRequest) {
			assert.Equal(http.StatusOK, res.Code)
		})

	// admin is allowed to access to admin path.
	r.GET("/admin/hello").
		SetHeader(gofight.H{
			authorizationHeaderKey: authorizationHeaderPrefix + adminToken,
		}).
		Run(handler, func(res gofight.HTTPResponse, req gofight.HTTPRequest) {
			assert.Equal(http.StatusOK, res.Code)
		})

	jwt.TimeFunc = time.Now
}

func TestNew(t *testing.T) {
	assert := assert.New(t)
	auth := Auth{}

	t.Run("if Authenticator is nil, return error", func(t *testing.T) {
		_, err := New(auth)
		assert.Error(err)
	})

	auth.Authenticator = func(c *gin.Context) (MapClaims, error) { return nil, nil }

	t.Run("if PayloadCreator is nil, return error", func(t *testing.T) {
		_, err := New(auth)
		assert.Error(err)
	})

	auth.UserFetcher = func(*gin.Context, MapClaims) (interface{}, error) { return nil, nil }

	t.Run("default values set correctly", func(t *testing.T) {
		a, err := New(auth)
		assert.NoError(err)
		assert.Equal("HS256", a.SigningMethod)
		assert.Equal(time.Hour, a.ExpiryInterval)
	})

	t.Run("be able to orverride default values", func(t *testing.T) {
		auth.SigningMethod = "changed"
		auth.ExpiryInterval = 2 * time.Hour
		a, err := New(auth)
		assert.NoError(err)
		assert.Equal("changed", a.SigningMethod)
		assert.Equal(2*time.Hour, a.ExpiryInterval)
	})
}

func TestVerifyPerm(t *testing.T) {
	assert := assert.New(t)

	auth, err := NewTestAuth()
	assert.NoError(err)

	t.Run("error is set in the Context if the Authorization Header is missing", func(t *testing.T) {
		c := newContext(http.Header{})

		auth.VerifyPerm(func(MapClaims) bool { return true })(c)

		assert.Equal(ErrorAuthorizationHeaderIsEmpty, errors.Cause(Error(c).(error)))
		assert.True(c.IsAborted())
	})

	t.Run("error is set in the Context if the Authorization Header is invalid", func(t *testing.T) {
		header := http.Header{}
		header.Set(authorizationHeaderKey, "Bearerinvalid-token")

		c := newContext(header)

		auth.VerifyPerm(func(MapClaims) bool { return true })(c)

		assert.Equal(ErrorAuthorizationHeaderIsInvalid, errors.Cause(Error(c).(error)))
		assert.True(c.IsAborted())
	})

	t.Run("error is set in the Context if the token expired", func(t *testing.T) {
		token, err := NewJWTToken()
		assert.NoError(err)

		header := http.Header{}
		header.Set(authorizationHeaderKey, authorizationHeaderPrefix+token)

		c := newContext(header)

		jwt.TimeFunc = func() time.Time { return time.Now().Add(2 * time.Hour) }

		auth.VerifyPerm(func(MapClaims) bool { return true })(c)

		assert.Equal(ErrorAuthorizationTokenExpired, errors.Cause(Error(c).(error)))
		assert.True(c.IsAborted())

		jwt.TimeFunc = time.Now
	})

	t.Run("error is set in the Context if the permission denied", func(t *testing.T) {
		token, err := NewJWTToken()
		assert.NoError(err)

		header := http.Header{}
		header.Set(authorizationHeaderKey, authorizationHeaderPrefix+token)

		c := newContext(header)

		auth.VerifyPerm(func(MapClaims) bool { return false })(c)

		_, ok := c.Get(PayloadKey)
		assert.True(ok)
		assert.Equal(ErrorPermissionDenied, errors.Cause(Error(c).(error)))
		assert.True(c.IsAborted())
	})

	t.Run("error is set in the Context if the UserFetcher returned error", func(t *testing.T) {
		token, err := NewJWTToken()
		assert.NoError(err)

		header := http.Header{}
		header.Set(authorizationHeaderKey, authorizationHeaderPrefix+token)

		c := newContext(header)

		expectedErr := errors.New("error")
		auth.UserFetcher = func(*gin.Context, MapClaims) (interface{}, error) { return nil, expectedErr }
		auth.VerifyPerm(func(MapClaims) bool { return true })(c)

		_, ok := c.Get(PayloadKey)
		assert.True(ok)
		assert.Equal(expectedErr, errors.Cause(Error(c).(error)))
		assert.True(c.IsAborted())
	})

	t.Run("error is set in the Context if the UserFetcher returned error", func(t *testing.T) {
		token, err := NewJWTToken()
		assert.NoError(err)

		header := http.Header{}
		header.Set(authorizationHeaderKey, authorizationHeaderPrefix+token)

		c := newContext(header)

		auth.UserFetcher = func(*gin.Context, MapClaims) (interface{}, error) { return nil, nil }
		auth.VerifyPerm(func(MapClaims) bool { return true })(c)

		_, ok := c.Get(PayloadKey)
		assert.True(ok)
		assert.Equal(ErrorUserNotFound, errors.Cause(Error(c).(error)))
		assert.True(c.IsAborted())
	})

	t.Run("error is set in the Context if the UserFetcher returned nil as user", func(t *testing.T) {
		token, err := NewJWTToken()
		assert.NoError(err)

		header := http.Header{}
		header.Set(authorizationHeaderKey, authorizationHeaderPrefix+token)

		c := newContext(header)

		auth.UserFetcher = func(*gin.Context, MapClaims) (interface{}, error) { return nil, nil }
		auth.VerifyPerm(func(MapClaims) bool { return true })(c)

		_, ok := c.Get(PayloadKey)
		assert.True(ok)
		assert.Equal(ErrorUserNotFound, errors.Cause(Error(c).(error)))
		assert.True(c.IsAborted())
	})

	t.Run("user is set in the Context", func(t *testing.T) {
		token, err := NewJWTToken()
		assert.NoError(err)

		header := http.Header{}
		header.Set(authorizationHeaderKey, authorizationHeaderPrefix+token)

		c := newContext(header)

		user := &TestUser{}
		auth.UserFetcher = func(*gin.Context, MapClaims) (interface{}, error) { return user, nil }
		auth.VerifyPerm(func(MapClaims) bool { return true })(c)

		assert.Nil(Error(c))
		assert.Equal(user, User(c))
	})
}

func newContext(header http.Header) *gin.Context {
	return &gin.Context{
		Request: &http.Request{
			Header: header,
		},
	}
}

func TestHandleParseTokenError(t *testing.T) {
	test := []struct {
		err error
	}{
		{ErrorAuthorizationHeaderIsEmpty},
		{ErrorAuthorizationHeaderIsInvalid},
		{errors.New("unexpected")},
	}
	for _, tt := range test {
		t.Run(fmt.Sprint("error:", tt.err), func(t *testing.T) {
			assert := assert.New(t)

			c := &gin.Context{}
			assert.True(handleParseTokenError(c, tt.err))
			assert.Equal(tt.err, Error(c))
		})
	}

	errTokExpired := &jwt.ValidationError{Errors: jwt.ValidationErrorExpired}
	t.Run(fmt.Sprint("error:", errTokExpired), func(t *testing.T) {
		assert := assert.New(t)

		c := &gin.Context{}
		assert.True(handleParseTokenError(c, errTokExpired))
		assert.Equal(ErrorAuthorizationTokenExpired, Error(c))
	})

	t.Run(fmt.Sprint("error:", nil), func(t *testing.T) {
		assert := assert.New(t)

		c := &gin.Context{}
		assert.False(handleParseTokenError(c, nil))
		assert.Nil(Error(c))
	})
}

func TestAuthenticateHandler(t *testing.T) {
	assert := assert.New(t)

	c := newContext(http.Header{})

	auth, err := NewTestAuth()
	assert.NoError(err)

	auth.Authenticator = func(c *gin.Context) (MapClaims, error) { return nil, ErrorAuthenticationFailed }
	auth.Authenticate(c)
	assert.Equal(ErrorAuthenticationFailed, errors.Cause(Error(c).(error)))
	assert.True(c.IsAborted())

	expectedErr := errors.New("expect")
	auth.Authenticator = func(c *gin.Context) (MapClaims, error) { return nil, expectedErr }
	auth.Authenticate(c)
	assert.Equal(expectedErr, errors.Cause(Error(c).(error)))
	assert.True(c.IsAborted())
}

func TestNewClaim(t *testing.T) {
	assert := assert.New(t)

	auth, err := NewTestAuth()
	assert.NoError(err)

	claims := MapClaims{
		"username": "username",
		"role":     OPERATOR,
	}

	claims1 := auth.refreshExp(claims)
	assert.Equal("username", claims1["username"])
	assert.Equal(OPERATOR, claims1["role"])
	assert.NotEmpty(claims1["exp"])
	assert.NotEmpty(claims1["iat"])

	auth.nowFunc = func() time.Time { return time.Now().Add(10 * time.Minute) }

	claims2 := auth.refreshExp(claims)
	assert.Equal(claims1["username"], claims2["username"])
	assert.Equal(claims1["role"], claims2["role"])
	assert.True(claims1["exp"].(int64) < claims2["exp"].(int64), fmt.Sprintf("old_exp=%d: new_exp=%d", claims1["exp"].(int64), claims2["exp"].(int64)))
	assert.True(claims1["iat"].(int64) < claims2["iat"].(int64), fmt.Sprintf("old_iat=%d: new_iat=%d", claims1["iat"].(int64), claims2["iat"].(int64)))
}

func TestUserFunc(t *testing.T) {
	assert.Nil(t, User(&gin.Context{}))
}
