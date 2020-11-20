# Build the manager binary
FROM golang:1.10.3 as builder

# Copy in the go src
WORKDIR /go/src/github.com/alphagov/verify-metadata-controller
COPY pkg/    pkg/
COPY cmd/    cmd/
COPY vendor/ vendor/

# Build
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -o manager github.com/alphagov/verify-metadata-controller/cmd/manager

FROM amazoncorretto:11

# Install AWS CloudHSM client and libs
ENV CLOUDHSM_CLIENT_VERSION=3.2.1-1.el7
RUN yum install -y wget tar gzip openssl \
 && wget --progress=bar:force https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/EL7/cloudhsm-client-${CLOUDHSM_CLIENT_VERSION}.x86_64.rpm \
 && yum install -y ./cloudhsm-client-*.rpm \
 && rm ./cloudhsm-client-*.rpm \
 && wget --progress=bar:force https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/EL7/cloudhsm-client-jce-${CLOUDHSM_CLIENT_VERSION}.x86_64.rpm \
 && yum install -y ./cloudhsm-client-jce-*.rpm \
 && rm ./cloudhsm-client-jce-*.rpm \
 && wget --progress=bar:force https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/EL7/cloudhsm-client-dyn-${CLOUDHSM_CLIENT_VERSION}.x86_64.rpm \
 && yum install -y ./cloudhsm-client-dyn-*.rpm \
 && sed -i 's/UNIXSOCKET/TCPSOCKET/g' /opt/cloudhsm/data/application.cfg

# install mdgen (signs metadata using hsm)
WORKDIR /buildjava

ENV GRADLE_USER_HOME=/build/.gradle
ENV LD_LIBRARY_PATH=/opt/cloudhsm/lib
ENV HSM_PARTITION=PARTITION_1
ENV HSM_USER=user
ENV HSM_PASSWORD=password

COPY gradlew ./gradlew
COPY build.gradle ./build.gradle
COPY settings.gradle ./settings.gradle
COPY gradle ./gradle

COPY mdgen/build.gradle                 ./mdgen/build.gradle
COPY mdgen/src                          ./mdgen/src
COPY mdgen/test                         ./mdgen/test

COPY cloudhsmtool/build.gradle         ./cloudhsmtool/build.gradle
COPY cloudhsmtool/src                  ./cloudhsmtool/src

RUN ./gradlew --console rich --parallel -Pcloudhsm --no-daemon

WORKDIR /

RUN mv /buildjava/cloudhsmtool/build/install/cloudhsmtool /cloudhsmtool
RUN mv /buildjava/mdgen/build/install/mdgen /mdgen
RUN rm -r /buildjava

# Copy the controller-manager into the image
COPY --from=builder /go/src/github.com/alphagov/verify-metadata-controller/manager .

ENTRYPOINT ["/manager"]
