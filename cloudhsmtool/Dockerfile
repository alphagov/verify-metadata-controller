FROM ubuntu:18.04

ENV CLASSPATH=/opt/cloudhsm/java/*
ENV HSM_PARTITION=PARTITION_1
ENV LD_LIBRARY_PATH=/opt/cloudhsm/lib

RUN apt-get update && apt-get install   wget \
                                        dnsutils \
                                        multiarch-support \
                                        libbsd0 \
                                        openjdk-11-jdk \
                                        python \
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
    wget http://de.archive.ubuntu.com/ubuntu/pool/main/libe/libedit/libedit2_3.1-20150325-1ubuntu2_amd64.deb && \
    dpkg -i *.deb

RUN /opt/cloudhsm/bin/configure -a $(dig +short afe8ce8bf61fb11eaa69a0af1fbe14c4-afb9ba656e22f14e.elb.eu-west-2.amazonaws.com | head -n 1)

COPY ./sandbox-customerCA.crt /opt/cloudhsm/etc/customerCA.crt
COPY ./src /cloudhsmtool/src
COPY gradlew /cloudhsmtool/gradlew
COPY settings.gradle /cloudhsmtool/settings.gradle
COPY build.gradle /cloudhsmtool/build.gradle
COPY ./gradle /cloudhsmtool/gradle
COPY ./gradle.properties /cloudhsmtool/gradle.properties

COPY script.bash /script.bash
RUN chmod +x /script.bash

WORKDIR /cloudhsmtool
RUN /cloudhsmtool/gradlew distZip

COPY ./sandbox-customerCA.crt /opt/cloudhsm/etc/customerCA.crt
WORKDIR /opt
RUN unzip /cloudhsmtool/build/distributions/cloudhsmtool.zip
RUN echo "alias hsmtool=\"java -cp \"/opt/cloudhsmtool/lib/*:/opt/cloudhsm/java/*\" uk.gov.ida.cloudhsmtool.CloudHSMTool $@\"" >> /root/.bashrc

CMD /script.bash
