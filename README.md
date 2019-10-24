# gin-jwt

[![GoDoc](https://godoc.org/github.com/kyfk/gin-jwt?status.svg)](https://godoc.org/github.com/kyfk/gin-jwt)
[![Build Status](https://cloud.drone.io/api/badges/kyfk/gin-jwt/status.svg)](https://cloud.drone.io/kyfk/gin-jwt)
[![Go Report Card](https://goreportcard.com/badge/github.com/kyfk/gin-jwt)](https://goreportcard.com/report/github.com/kyfk/gin-jwt)
[![codecov](https://codecov.io/gh/kyfk/gin-jwt/branch/master/graph/badge.svg)](https://codecov.io/gh/kyfk/gin-jwt)
[![codebeat badge](https://codebeat.co/badges/d45a5e1a-6745-4945-8201-7d9f256fb817)](https://codebeat.co/projects/github-com-kyfk-gin-jwt-master)


This is the simplest authorization/authentication middleware for [Gin Web Framework](https://github.com/gin-gonic/gin).

It uses [jwt-go](github.com/dgrijalva/jwt-go) to provide a jwt authentication middleware.

It provides additional bellow 3 handlers:
- [**Authenticate**](https://godoc.org/github.com/kyfk/gin-jwt#Auth.Authenticate) (for issuing a token)
- [**RefreshToken**](https://godoc.org/github.com/kyfk/gin-jwt#Auth.RefreshToken) (for refreshing a expiration of token)
- [**VerifyPerm**](https://godoc.org/github.com/kyfk/gin-jwt#Auth.VerifyPerm) (the helper for verify permission)

It uses **only** `Authorization` HTTP header to exchange a token.

## Installation

```
$ go get github.com/kyfk/gin-jwt
```

## Example

See the [Complete Example](https://github.com/kyfk/git-jwt/blob/master/example/main.go) for more details.

```go
func main() {
    auth, err := jwt.New(jwt.Auth{
        SecretKey: []byte("must change here"),

        // Authenticator authenticates a request and return jwt.MapClaims
        // that contains a user information of the request.
        Authenticator: func(c *gin.Context) (jwt.MapClaims, error) {
            var loginForm LoginForm
            if err := c.ShouldBind(&loginForm); err != nil {
                return nil, jwt.ErrorAuthenticationFailed
            }

            u, ok := authenticate(req.Username, req.Password)
            if ok {
                return nil, jwt.ErrorAuthenticationFailed
            }

            return jwt.MapClaims{
                "username": u.Username,
                "role":     u.Role,
            }, nil
        },

        // UserFetcher takes a jwt.MapClaims and return a user object.
        UserFetcher: func(c *gin.Context, claims jwt.MapClaims) (interface{}, error) {
            username, ok := claims["username"].(string)
            if !ok {
                return nil, nil
            }
            return findByUsername(username)
        },
    })

    // some lines

    e.Use(jwt.ErrorHandler)

    // issue authorization token
    e.POST("/login", auth.AuthenticateHandler)

    // refresh token expiration
    e.POST("/auth/refresh_token", auth.RefreshHandler)

    // role management
    e.GET("/operator/hello", Operator(auth), SayHello) // this is only for Operator
    e.GET("/admin/hello", Admin(auth), SayHello) // this is only for Admin
}
```

## Error Handling

The handlers set an error into the gin.Context if it occurred.

Let's see the [ErrorHandler](https://github.com/kyfk/gin-jwt/blob/master/jwt.go#L46-L70).
That's middleware for error handling.

If you want to handle errors yourself, copy above middleware and fix it.

## Inspired By

- https://github.com/appleboy/gin-jwt

Appleboy's repository provides authorization features.
Although I wanted a more flexible feature to manage several roles.
Finally, I decided to create this repository.
