#!/bin/bash
about_env_vars() {
    echo "Try HSM_USER=<some user name> HSM_PASSWORD=<some password> $0"
}

if [ "$HSM_USER" = "" ]
then
    echo \$HSM_USER was not set.
    about_env_vars
    exit 1
fi

if [ "$HSM_PASSWORD" = "" ]
then
    echo \$HSM_PASSWORD was not set.
    about_env_vars
    exit 1
fi

docker run -e HSM_USER -e HSM_PASSWORD -it cloudhsmtool:docker