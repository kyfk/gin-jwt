package jwt

import (
	"log"
	"net/http"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
)

const (
	// ErrKey is used to set error into gin.Context.
	ErrKey = "GIN_JWT_ERROR"
	// PayloadKey is used to set payload of jwt token into gin.Context.
	PayloadKey = "GIN_JWT_PAYLOAD"
	// TokenKey is used to set a jwt token into gin.Context.
	TokenKey = "GIN_JWT_TOKEN"
	// UserKey is used to set a user into gin.Context.
	UserKey = "GIN_JWT_USER"

	authorizationHeaderKey    = "Authorization"
	authorizationHeaderPrefix = "Bearer "
)

// MapClaims is alias of github.com/dgrijalva/jwt-go.MapClaims.
type MapClaims = jwt.MapClaims

var (
	// ErrorAuthorizationHeaderIsEmpty is a error in the case of Authorization header is empty.
	ErrorAuthorizationHeaderIsEmpty = errors.New("Authorization header is empty")

	// ErrorAuthorizationHeaderIsInvalid is a error in the case of Authorization header isn't valid.
	ErrorAuthorizationHeaderIsInvalid = errors.New("Authorization header is invalid")

	// ErrorAuthorizationTokenExpired is an error in the case of Authorization token is expired.
	ErrorAuthorizationTokenExpired = errors.New("Authorization token is expired")

	// ErrorAuthenticationFailed is an error at authentication is failed.
	ErrorAuthenticationFailed = errors.New("Authentication failled")

	// ErrorPermissionDenied is a error at permission is denied.
	ErrorPermissionDenied = errors.New("permission is denied")

	// ErrorUserNotFound is an error in the case of a user not found.
	ErrorUserNotFound = errors.New("user not found")
)

// ErrorHandler handles gin-jwt's errors from gin.Context.
func ErrorHandler(c *gin.Context) {
	c.Next()

	err := Error(c)
	if err == nil {
		return
	}

	switch err {
	// status 401
	case ErrorAuthorizationHeaderIsEmpty,
		ErrorAuthorizationHeaderIsInvalid,
		ErrorAuthorizationTokenExpired,
		ErrorAuthenticationFailed:
		log.Println(err)

	// status 403
	case ErrorPermissionDenied:
		log.Println(err)

	// status 500
	default:
		log.Println(err)
	}
}

// Auth provides useful authorization/authentication functions.
type Auth struct {
	// ExpiryInterval is an interval of expiration that is used to calculate the `exp` claim of JWT.
	ExpiryInterval time.Duration
	// SigningMethod is a method of the signing of JWT token. default is `HS256`.
	SigningMethod string
	// SecretKey is a secret key for signing JWT.
	SecretKey []byte
	// Authenticator authenticates a request and return jwt.MapClaims
	// that contains a user information of the request.
	Authenticator func(c *gin.Context) (MapClaims, error)
	// UserFetcher takes a jwt.MapClaims and return a user object.
	UserFetcher func(MapClaims) (interface{}, error)

	// this is for testing.
	nowFunc func() time.Time
}

// New returns initialized Auth.
// If Authenticator or UserFetcher are nil, return the error.
func New(a Auth) (Auth, error) {
	if a.Authenticator == nil {
		return Auth{}, errors.New("missing Auth.Authenticator")
	}
	if a.UserFetcher == nil {
		return Auth{}, errors.New("missing Auth.UserFetcher")
	}
	if a.SigningMethod == "" {
		a.SigningMethod = "HS256"
	}
	if a.ExpiryInterval == 0 {
		a.ExpiryInterval = time.Hour
	}
	a.nowFunc = time.Now
	return a, nil
}

// VerifyPerm is used to pass a MapClaim to a authorization function.
// After authorization, use UserFetcher to get a user object by identity,
// and set it into the gin.Context.
func (a Auth) VerifyPerm(permitted func(MapClaims) bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := a.parseToken(c)
		if handleParseTokenError(c, err) {
			c.Abort()
			return
		}

		claims := token.Claims.(MapClaims)

		// set payload to context for debug
		c.Set(PayloadKey, claims)

		if !permitted(claims) {
			c.Set(ErrKey, ErrorPermissionDenied)
			c.Status(http.StatusForbidden)
			c.Abort()
			return
		}

		u, err := a.UserFetcher(claims)
		if err != nil {
			c.Set(ErrKey, err)
			c.Status(http.StatusInternalServerError)
			c.Abort()
			return
		}
		if u == nil {
			c.Set(ErrKey, ErrorUserNotFound)
			c.Status(http.StatusInternalServerError)
			c.Abort()
			return
		}

		c.Set(UserKey, u)
		c.Next()
	}
}

// Authenticate can be used by clients to get a jwt token.
// Authenticator of Auth is used in this method to authenticate a user request.
// Authorization token that is a form of `Authorization: Bearer <TOKEN>` is supplied
// in a response header.
func (a Auth) Authenticate(c *gin.Context) {
	claims, err := a.Authenticator(c)
	if err != nil {
		c.Set(ErrKey, err)
		c.Status(http.StatusUnauthorized)
		c.Abort()
		return
	}
	a.respondAuthorizationHeader(c, claims)
}

// RefreshToken can be used to refresh a token. The token still needs to be valid on refresh.
// Authorization token that is a form of `Authorization: Bearer <TOKEN>` is supplied
// in a response header.
func (a Auth) RefreshToken(c *gin.Context) {
	token, err := a.parseToken(c)
	if handleParseTokenError(c, err) {
		c.Abort()
		return
	}
	a.respondAuthorizationHeader(c, token.Claims.(MapClaims))
}

// respondAuthorizationHeader create a authorization token and set it in the response header.
func (a Auth) respondAuthorizationHeader(c *gin.Context, claims MapClaims) {
	newToken := jwt.New(jwt.GetSigningMethod(a.SigningMethod))
	newToken.Claims = a.refreshExp(claims)
	tokenString, err := newToken.SignedString(a.SecretKey)
	if err != nil {
		c.Set(ErrKey, err)
		c.Status(http.StatusInternalServerError)
		return
	}

	c.Header(authorizationHeaderKey, authorizationHeaderPrefix+tokenString)
	c.Status(http.StatusOK)
}

func (a Auth) parseToken(c *gin.Context) (*jwt.Token, error) {
	tokenStr, err := a.authToken(c.Request.Header)
	if err != nil {
		return nil, err
	}

	// set token string to context for debug.
	c.Set(TokenKey, tokenStr)

	return a._parseToken(tokenStr)
}

// _parseToken is separated from the `parseToken` function because it's used for testing.
func (a Auth) _parseToken(token string) (*jwt.Token, error) {
	return jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		return a.SecretKey, nil
	})
}

// Extract a token string from a request header.
func (a Auth) authToken(header http.Header) (string, error) {
	authHeader := header.Get(authorizationHeaderKey)
	if authHeader == "" {
		return "", errors.WithStack(ErrorAuthorizationHeaderIsEmpty)
	}

	if !strings.HasPrefix(authHeader, authorizationHeaderPrefix) {
		return "", errors.WithStack(ErrorAuthorizationHeaderIsInvalid)
	}
	return strings.TrimPrefix(authHeader, authorizationHeaderPrefix), nil
}

// handleParseTokenError is used for error handling of parseToken.
func handleParseTokenError(c *gin.Context, err error) bool {
	switch errors.Cause(err) {
	case ErrorAuthorizationHeaderIsEmpty, ErrorAuthorizationHeaderIsInvalid:
		c.Status(http.StatusForbidden)
		c.Set(ErrKey, err)
		return true
	}
	validationErr, ok := err.(*jwt.ValidationError)
	if ok && validationErr.Errors == jwt.ValidationErrorExpired {
		c.Status(http.StatusUnauthorized)
		c.Set(ErrKey, ErrorAuthorizationTokenExpired)
		return true
	}
	if err != nil {
		c.Status(http.StatusInternalServerError)
		c.Set(ErrKey, err)
		return true
	}
	return false
}

// refreshExp refreshes `exp` and `iat`.
func (a Auth) refreshExp(claims MapClaims) MapClaims {
	newClaims := MapClaims{}
	for k, v := range claims {
		newClaims[k] = v
	}
	now := a.nowFunc()
	expire := now.Add(a.ExpiryInterval)
	newClaims["exp"] = expire.Unix()
	newClaims["iat"] = now.Unix()
	return newClaims
}

// Error extracts a error from gin.Context.
func Error(c *gin.Context) interface{} {
	v, ok := c.Get(ErrKey)
	if !ok {
		return nil
	}
	return v
}

// User extracts the user object from gin.Context that VerifyPerm set.
func User(c *gin.Context) interface{} {
	v, ok := c.Get(UserKey)
	if !ok {
		return nil
	}
	return v
}
