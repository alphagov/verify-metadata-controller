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
RUN yum install -y wget tar gzip \
 && wget https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/EL7/cloudhsm-client-latest.el7.x86_64.rpm \
 && yum install -y ./cloudhsm-client-latest.*.rpm \
 && rm ./cloudhsm-client-latest.*.rpm \
 && wget https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/EL7/cloudhsm-client-jce-latest.el7.x86_64.rpm \
 && yum install -y ./cloudhsm-client-jce-latest.*.rpm \
 && rm ./cloudhsm-client-jce-latest.*.rpm \
 && wget https://download.java.net/java/GA/jdk11/9/GPL/openjdk-11.0.2_linux-x64_bin.tar.gz \
 && mkdir -p /usr/lib/jvm \
 && tar -C /usr/lib/jvm -xf ./openjdk-11.0.2*.tar.gz \
 && rm ./openjdk-11.0.2*.tar.gz \
 && sed -i 's/UNIXSOCKET/TCPSOCKET/g' /opt/cloudhsm/data/application.cfg

WORKDIR /mdgen
ENV GRADLE_USER_HOME=/build/.gradle \
    LD_LIBRARY_PATH=/opt/cloudhsm/lib \
    HSM_PARTITION=PARTITION_1 \
    HSM_USER=user \
    HSM_PASSWORD=password \
    JAVA_HOME=/usr/lib/jvm/jdk-11.0.2
COPY mdgen/gradlew ./gradlew
COPY mdgen/build.gradle ./build.gradle
COPY mdgen/settings.gradle ./settings.gradle
COPY mdgen/gradle ./gradle
COPY mdgen/src ./src
RUN ./gradlew -Pcloudhsm --no-daemon installDist -x test

WORKDIR /
# Copy the controller-manager into the image
COPY --from=builder /go/src/github.com/alphagov/verify-metadata-controller/manager .

# install openssl dynamic engine tools
RUN yum install -y openssl \
	&& wget https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/EL7/cloudhsm-client-dyn-latest.el7.x86_64.rpm \
	&& yum install -y ./cloudhsm-client-dyn-latest.el7.x86_64.rpm

ENTRYPOINT ["/manager"]
