#!/bin/bash

# some docker commands

# Start docker
dcbuild
dcup

# show all containers
docker container ls

# connect - you can use tab to autocomplete the NAME
docker exec -it NAME bash

# stop 1 container
docker container stop NAME

# stop all containers
docker stop $(docker ps -a -q)
