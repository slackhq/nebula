# NebulaOSS/nebula Docker Image

## Building

From the root of the repository, run `make docker`.

## Running

To run the built image, use the following command:

```
docker run \
    --name nebula \
    --network host \
    --cap-add NET_ADMIN \
    --volume ./config:/config \
    --rm \
    nebulaoss/nebula
```

A few notes:

- The `NET_ADMIN` capability is necessary to create the tun adapter on the host (this is unnecessary if the tun device is disabled.)
- `--volume ./config:/config` should point to a directory that contains your `config.yml` and any other necessary files.
