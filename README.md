# neofs-send-authz
send.fs.neo.org authentication backend


## Build
To build binary run the following command:
```
$ make
```

### Configuration
To successful connection to google, github and etc. oauth service fill **config.yaml** with your app credentials:

```
oauth:
  google:
    id: "google id"
    secret: "google secret"
    scopes:
      - "https://www.googleapis.com/auth/userinfo.email"
    endpoint:
      auth: "https://accounts.google.com/o/oauth2/auth"
      token: "https://oauth2.googleapis.com/token"

  github:
    id: "github id"
    secret: "github secret"
    scopes:
    endpoint:
      auth: "https://github.com/login/oauth/authorize"
      token: "https://github.com/login/oauth/access_token"

```

### Run
After build you can run the app (**note:** config.yaml must be in the directory where the application is going to be launched.
In the following example it must be **"./config.yaml"**):

```
./bin/neofs-send-authz -p s01.neofs.devenv:8080 --key KxDgvEKzgSBPPfuVfw67oPQBSjidEiqTHURKSDL1R7yGaGYAeYnr --owner_id NQydaT4iTL9rCuUbRL5GZ2phCopxX9yJYY --cid 2Z4mjBwgm1wVoFDeMDvWMgLqqLrVhgSm5RtDG6uAo7Jj --listen_address localhost:8083 
```

Arguments:

```
-p s01.neofs.devenv:8080 // neofs node connection endpoint to get current epoch
--key KxDgvEKzgSBPPfuVfw67oPQBSjidEiqTHURKSDL1R7yGaGYAeYnr // key to sing bearer token (must be container owner key)
--cid 2Z4mjBwgm1wVoFDeMDvWMgLqqLrVhgSm5RtDG6uAo7Jj // container id (used to fill correspond field in the bearer token)
--owner_id NQydaT4iTL9rCuUbRL5GZ2phCopxX9yJYY // owner token id (used to fill correspond field in the bearer token)
--listen_address localhost:8083 // address to start server
```
