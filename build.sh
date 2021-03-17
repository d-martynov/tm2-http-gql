#!/usr/bin/env bash
cd "$(dirname "$0")/build" || exit
export BRANCH=$(git rev-parse --abbrev-ref HEAD)
docker-compose build && docker-compose push
