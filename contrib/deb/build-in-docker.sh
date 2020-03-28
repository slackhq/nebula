#!/bin/bash
# Thin wrapper to build debs with provided Dockerfile and copy results to host
# execute with --no-cache to make a complete re-build
#
# Author: Michael Gebetsroither <michael@mgeb.org>
# This script is published under MIT License

IMAGE_="nebula_builder"

docker build $* -t "$IMAGE_" .
container_id_=$(docker run -dt "$IMAGE_")

docker cp "$container_id_":/out/ ../
docker stop "$container_id_"
