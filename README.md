# neofs-oauthz
neofs-oauthz is an authentication backend allowing to login to NeoFS network
via Google or Github OAuth 2.0. It checks the user and then generates a bearer
token to allow uploading files with user's e-mail specified in
attributes. There is no fancy key management there, but at the same time it
allows to identify each object's uploader which is the main purpose for it
now. This backend is currently used by https://send.fs.neo.org/ demo.

## Installation
1. To build the binary run the following command:
```
$ make
```
2. To build the docker image
```
make image
```

## Execution
neofs-oauthz must be run with `.yaml` config file:
```
$ ./neofs-oauthz -c config.yaml
```
or environment variables
```
NEOFS_OAUTHZ_CONFIG=config.yaml ./neofs-oauthz
```

## Configuration
Example of the configuration file: [config/config.yaml](/config/config.yaml)

Now the app supports authentication via `github` and `google` services.

### General section
```
redirect:
  url:  "/"

listen_address: 0.0.0.0:8083

logger:
    level: debug

connect_timeout: 30s
request_timeout: 15s
rebalance_timer: 15s
```
| Parameter         | Type       | Default value | Description                                                                                        |
|-------------------|------------|---------------|----------------------------------------------------------------------------------------------------|
| `bearer_cookie_name`| `string` | `Bearer`      | The name of the cookie holding bearer token.                                                       |
| `redirect.url`    | `string`   |               | URL to redirect users going through the OAuth flow                                                 |
| `listen_address`  | `string`   |               | The address that the app is listening on.                                                          |
| `logger.level`    | `string`   | `debug`       | Logging level.<br/>Possible values:  `debug`, `info`, `warn`, `error`, `dpanic`, `panic`, `fatal`. |
| `connect_timeout` | `duration` | `30s`         | Timeout to connect to a node.                                                                      |
| `request_timeout` | `duration` | `15s`         | Timeout to check node health during rebalance.                                                     |
| `rebalance_timer` | `duration` | `15s`         | Interval to check node health.                                                                     |

### NeoFS section
```
neofs:
  wallet:
    path: /path/to/wallet.json
    address:  NfgHwwTi3wHAS8aFAN243C5vGbkYDpqLHP # Account address. If omitted default one will be used.
    passphrase: '' # Passphrase to decrypt wallet. If you're using a wallet without a password, place '' here.
  cid: 2qAEwyRwV1sMmq8pc32mKCt1SRmTBXrzP9KbfMoHmqYM
  bearer_user_id: NUVPACMnKFhpuHjsRjhUvXz1XhqfGZYVtY
  bearer_email_attribute: email
```
| Parameter                 | Type     | Default value | Description                                                              |
|---------------------------|----------|---------------|--------------------------------------------------------------------------|
| `neofs.wallet.path`       | `string` |               | Path to the wallet.                                                      |
| `neofs.wallet.address`    | `string` |               | Account address to get from wallet. If omitted default one will be used. |
| `neofs.wallet.passphrase` | `string` |               | Passphrase to decrypt wallet.                                            |
| `neofs.cid`               | `string` |               | container ID in NeoFS where objects will be stored                       |
| `neofs.bearer_user_id`    | `string` |               | User ID that will be given the right to upload objects into NeoFS container (can be omitted to allow this for any owner of the token) |
| `neofs.bearer_email_attribute`| `string`| `Email`    | The name of the NeoFS attribute used as to match user by his e-mail address (case sensitive as all NeoFS attributes) |

### NeoFS nodes section
```
peers:
  0:
    address: node1.neofs:8080
    priority: 1
    weight: 1
  1:
    address: node2.neofs:8080
    priority: 2
    weight: 0.1
  2:
    address: node3.neofs:8080
    priority: 2
    weight: 0.9
```
| Parameter  | Type     | Default value | Description                                                                                                                                             |
|------------|----------|---------------|---------------------------------------------------------------------------------------------------------------------------------------------------------|
| `address`  | `string` |               | Address of storage node.                                                                                                                                |
| `priority` | `int`    | `1`           | It allows to group nodes and don't switch group until all nodes with the same priority will be unhealthy. The lower the value, the higher the priority. |
| `weight`   | `float`  | `1`           | Weight of node in the group with the same priority. Distribute requests to nodes proportionally to these values.                                        |
