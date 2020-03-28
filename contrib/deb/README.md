# Building Debian Packages

If you have `fpm` installed on your host just execute `build-deb.sh`.

If not, execute `build-in-docker.sh`

## Schematics

`build-in-docker.sh` ... wrapper script to execute `build-deb.sh` in docker

`Dockerfile` ... create debian based build system with fpm installed and executes `build-deb.sh`

`build-deb.sh` ... script to downlaod a nebula release and create a debian package using `fpm`

## Call Chain

```
build-in-docker.sh
   -> docker build (Dockerfile)
      -> build-deb.sh
build-in-docker.sh (copy result to host)
```

## FAQ

### I want to integrated it into my CI/CD

- look at `build-in-docker.sh` and put the cmds used there into your CI/CD workflow
- if you put the "build context" where results are collected from your CI/CD to `/out` the nubula deb will be delivered directly into your workflow
