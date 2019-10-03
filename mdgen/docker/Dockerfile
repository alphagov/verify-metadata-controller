FROM ubuntu:18.04

ENV CLASSPATH=/opt/cloudhsm/java/*

RUN apt-get update
RUN apt-get install wget \
                    dnsutils \
                    multiarch-support \
                    libbsd0 \
                    openjdk-11-jre \
                    python \
                    ruby-dev \
                    rbenv \
                    ruby-build \
                    git \
                    autoconf \
                    bison \
                    -y

RUN wget https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/Xenial/cloudhsm-client_latest_amd64.deb && \
    wget https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/Xenial/cloudhsm-client-jce_latest_amd64.deb && \
    wget https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/Xenial/cloudhsm-client-dyn_latest_amd64.deb && \
    wget http://de.archive.ubuntu.com/ubuntu/pool/main/j/json-c/libjson-c2_0.11-4ubuntu2_amd64.deb && \
    wget http://de.archive.ubuntu.com/ubuntu/pool/main/libe/libedit/libedit2_3.1-20150325-1ubuntu2_amd64.deb
RUN dpkg -i *.deb

RUN rbenv install 2.4.1

COPY ./sandbox-customerCA.crt /opt/cloudhsm/etc/customerCA.crt
COPY ./start.bash /start.bash

ENTRYPOINT [ "/bin/bash", "/start.bash" ]
