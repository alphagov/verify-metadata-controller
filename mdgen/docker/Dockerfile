FROM ubuntu:18.04
COPY ./sandbox-customerCA.crt /opt/cloudhsm/etc/customerCA.crt
RUN apt-get update
RUN apt-get install wget dnsutils -y
RUN apt-get install multiarch-support libbsd0 -y
RUN wget https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/Xenial/cloudhsm-client_latest_amd64.deb
RUN wget https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/Xenial/cloudhsm-client-jce_latest_amd64.deb
RUN wget https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/Xenial/cloudhsm-client-dyn_latest_amd64.deb
RUN wget http://de.archive.ubuntu.com/ubuntu/pool/main/j/json-c/libjson-c2_0.11-4ubuntu2_amd64.deb
RUN wget http://de.archive.ubuntu.com/ubuntu/pool/main/libe/libedit/libedit2_3.1-20150325-1ubuntu2_amd64.deb
RUN dpkg -i libjson-c2_0.11-4ubuntu2_amd64.deb
RUN dpkg -i libedit2_3.1-20150325-1ubuntu2_amd64.deb
RUN apt-get install libjson-c2 libedit2 -y
RUN dpkg -i cloudhsm-client_latest_amd64.deb
RUN dpkg -i cloudhsm-client-jce_latest_amd64.deb
RUN dpkg -i cloudhsm-client-dyn_latest_amd64.deb
RUN apt-get install openjdk-11-jre -y
RUN apt-get install python -y
RUN apt-get install ruby-dev -y
RUN /opt/cloudhsm/bin/configure -a $(dig +short a88bb4c07943b11e9bbf30ae9bf7a1ac-aa921f50a00f6c2a.elb.eu-west-2.amazonaws.com)
RUN apt-get install rbenv ruby-build -y
RUN apt-get install git autoconf bison -y
RUN rbenv install 2.4.1
COPY ./start.bash /start.bash
RUN export CLASSPATH=/opt/cloudhsm/java/*
ENTRYPOINT [ "/bin/bash", "/start.bash" ]
