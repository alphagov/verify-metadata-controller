FROM ubuntu:18.04

ENV CLASSPATH=/opt/cloudhsm/java/*
ENV CLOUDHSM_CLIENT_VERSION=3.2.1-1

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

RUN wget https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/Xenial/cloudhsm-client_${CLOUDHSM_CLIENT_VERSION}_amd64.deb && \
    wget https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/Xenial/cloudhsm-client-jce_${CLOUDHSM_CLIENT_VERSION}_amd64.deb && \
    wget https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/Xenial/cloudhsm-client-dyn_${CLOUDHSM_CLIENT_VERSION}_amd64.deb && \
    wget http://de.archive.ubuntu.com/ubuntu/pool/main/j/json-c/libjson-c2_0.11-4ubuntu2_amd64.deb && \
    wget http://de.archive.ubuntu.com/ubuntu/pool/main/libe/libedit/libedit2_3.1-20150325-1ubuntu2_amd64.deb
RUN dpkg -i *.deb

RUN /opt/cloudhsm/bin/configure -a $(dig +short afe8ce8bf61fb11eaa69a0af1fbe14c4-afb9ba656e22f14e.elb.eu-west-2.amazonaws.com | head -n 1)

RUN rbenv install 2.4.1

COPY ./sandbox-customerCA.crt /opt/cloudhsm/etc/customerCA.crt
COPY ./start.bash /start.bash

ENTRYPOINT [ "/bin/bash", "/start.bash" ]
