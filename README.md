# neofs-send-authz
neofs-send-authz is backend which allows to login to NeoFS network via Google or Github OAuth 2.0.  

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
neofs-send-authz must be run with `.yaml` config file:
```
$ ./neofs-send-authz -c config.yaml
```
or environment variables
```
SEND_AUTHZ_CONFIG=config.yaml ./neofs-send-authz
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
  owner_id: NfgHwwTi3wHAS8aFAN243C5vGbkYDpqLHP
```
| Parameter                 | Type     | Default value | Description                                                              |
|---------------------------|----------|---------------|--------------------------------------------------------------------------|
| `neofs.wallet.path`       | `string` |               | Path to the wallet.                                                      |
| `neofs.wallet.address`    | `string` |               | Account address to get from wallet. If omitted default one will be used. |
| `neofs.wallet.passphrase` | `string` |               | Passphrase to decrypt wallet.                                            |
| `neofs.cid`               | `string` |               | container ID in NeoFS where objects will be stored                       |
| `neofs.owner_id`          | `string` |               | user ID which will be used to manage objects in a NeoFS container        |

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
