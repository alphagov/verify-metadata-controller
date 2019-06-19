# Build the manager binary
FROM golang:1.10.3 as builder

# Copy in the go src
WORKDIR /go/src/github.com/alphagov/verify-metadata-controller
COPY pkg/    pkg/
COPY cmd/    cmd/
COPY vendor/ vendor/

# Build
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -o manager github.com/alphagov/verify-metadata-controller/cmd/manager

FROM amazonlinux:2.0.20190212

# Install AWS CloudHSM client and libs
ENV CLOUDHSM_CLIENT_VERSION=2.0.3-3.el7
RUN yum install -y wget tar gzip openssl \
 && wget https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/EL7/cloudhsm-client-${CLOUDHSM_CLIENT_VERSION}.x86_64.rpm \
 && yum install -y ./cloudhsm-client-*.rpm \
 && rm ./cloudhsm-client-*.rpm \
 && wget https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/EL7/cloudhsm-client-jce-${CLOUDHSM_CLIENT_VERSION}.x86_64.rpm \
 && yum install -y ./cloudhsm-client-jce-*.rpm \
 && rm ./cloudhsm-client-jce-*.rpm \
 && wget https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/EL7/cloudhsm-client-dyn-${CLOUDHSM_CLIENT_VERSION}.x86_64.rpm \
 && yum install -y ./cloudhsm-client-dyn-*.rpm \
 && wget https://download.java.net/java/GA/jdk11/9/GPL/openjdk-11.0.2_linux-x64_bin.tar.gz \
 && mkdir -p /usr/lib/jvm \
 && tar -C /usr/lib/jvm -xf ./openjdk-11.0.2*.tar.gz \
 && rm ./openjdk-11.0.2*.tar.gz \
 && sed -i 's/UNIXSOCKET/TCPSOCKET/g' /opt/cloudhsm/data/application.cfg

# install mdgen (signs metadata using hsm)
WORKDIR /mdgen
ENV GRADLE_USER_HOME=/build/.gradle
ENV LD_LIBRARY_PATH=/opt/cloudhsm/lib
ENV HSM_PARTITION=PARTITION_1
ENV HSM_USER=user
ENV HSM_PASSWORD=password
ENV JAVA_HOME=/usr/lib/jvm/jdk-11.0.2
ENV PATH="${PATH}:${JAVA_HOME}/bin"
COPY mdgen/gradlew ./gradlew
COPY mdgen/build.gradle ./build.gradle
COPY mdgen/settings.gradle ./settings.gradle
COPY mdgen/gradle ./gradle
COPY mdgen/src ./src
RUN ./gradlew -Pcloudhsm --no-daemon installDist -x test

# install cloudhsm tool (generates keys etc)
WORKDIR /cloudhsmtool
ENV GRADLE_USER_HOME=/build/.gradle
COPY cloudhsmtool/gradlew ./gradlew
COPY cloudhsmtool/build.gradle ./build.gradle
COPY cloudhsmtool/settings.gradle ./settings.gradle
COPY cloudhsmtool/gradle ./gradle
COPY cloudhsmtool/src ./src
RUN ./gradlew -Pcloudhsm --no-daemon installDist -x test

# Copy the controller-manager into the image
WORKDIR /
COPY --from=builder /go/src/github.com/alphagov/verify-metadata-controller/manager .

ENTRYPOINT ["/manager"]
