# Example

### 1. Launch the example application.

```
$ go run ./main.go
[GIN-debug] [WARNING] Running in "debug" mode. Switch to "release" mode in production.
 - using env:	export GIN_MODE=release
 - using code:	gin.SetMode(gin.ReleaseMode)

[GIN-debug] POST   /login                    --> github.com/kyfk/gin-jwt.Auth.Authenticate-fm (2 handlers)
[GIN-debug] POST   /auth/refresh_token       --> github.com/kyfk/gin-jwt.Auth.RefreshToken-fm (2 handlers)
[GIN-debug] GET    /operator/hello           --> main.SayHello (3 handlers)
[GIN-debug] GET    /admin/hello              --> main.SayHello (3 handlers)
[GIN-debug] GET    /system_admin/hello       --> main.SayHello (3 handlers)
```

### 2. Issue a auth token of the operator user.

The auth token is returned in `Authorization` response header.

```
$ curl -v -POST -H "Content-Type: application/json" http://localhost:3000/login -d '{"username": "operator", "password": "operator"}'
*   Trying ::1:3000...
* TCP_NODELAY set
* Connected to localhost (::1) port 3000 (#0)
> POST /login HTTP/1.1
> Host: localhost:3000
> User-Agent: curl/7.65.3
> Accept: */*
> Content-Type: application/json
> Content-Length: 48
>
* upload completely sent off: 48 out of 48 bytes
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NzE2NjI3NDIsImlhdCI6MTU3MTY1OTE0Miwicm9sZSI6MSwidXNlcm5hbWUiOiJvcGVyYXRvciJ9.cZFA2YOUnijg22GanaFyXHsMotalQGPnuCsIV_DuWD4     <-------- here
< Date: Mon, 21 Oct 2019 11:59:02 GMT
< Content-Length: 0
<
* Connection #0 to host localhost left intact
```


### 3. Try to access endpoints using the auth token issued in 2.

```
# succeed to get information
$ curl -H "Authorization: Bearer <THE_TOKEN_ISSURED>" http://localhost:3000/operator/hello
{"user":{"username":"operator","email":"o@o.com"}}

# access denied
$ curl -v -H "Authorization: Bearer <THE_TOKEN_ISSURED>" http://localhost:3000/admin/hello
*   Trying ::1:3000...
* TCP_NODELAY set
* Connected to localhost (::1) port 3000 (#0)
> GET /admin/hello HTTP/1.1
> Host: localhost:3000
> User-Agent: curl/7.65.3
> Accept: */*
> Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NzE2NjI3NDIsImlhdCI6MTU3MTY1OTE0Miwicm9sZSI6MSwidXNlcm5hbWUiOiJvcGVyYXRvciJ9.cZFA2YOUnijg22GanaFyXHsMotalQGPnuCsIV_DuWD4
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 403 Forbidden
< Date: Mon, 21 Oct 2019 12:00:21 GMT
< Content-Length: 0
<
* Connection #0 to host localhost left intact
```

### :ex

Also you can try admin role

```
$ curl -v -POST -H "Content-Type: application/json" http://localhost:3000/login -d '{"username": "admin", "password": "admin"}'
*   Trying ::1:3000...
* TCP_NODELAY set
* Connected to localhost (::1) port 3000 (#0)
> POST /login HTTP/1.1
> Host: localhost:3000
> User-Agent: curl/7.65.3
> Accept: */*
> Content-Type: application/json
> Content-Length: 42
>
* upload completely sent off: 42 out of 42 bytes
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NzE2NjMxMjAsImlhdCI6MTU3MTY1OTUyMCwicm9sZSI6MywidXNlcm5hbWUiOiJhZG1pbiJ9.hMxBYG6lLNHQfguXoDFebkQxRjLDZ_7ayGB0r2v6oKw
< Date: Mon, 21 Oct 2019 12:05:20 GMT
< Content-Length: 0
<
* Connection #0 to host localhost left intact
```
