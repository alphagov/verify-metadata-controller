#!/bin/bash
export LD_LIBRARY_PATH=/opt/cloudhsm/lib
export HSM_PARTITION=PARTITION_1
hsm_ip_address=$(dig +short a88bb4c07943b11e9bbf30ae9bf7a1ac-aa921f50a00f6c2a.elb.eu-west-2.amazonaws.com | head -n 1)
/opt/cloudhsm/bin/configure -a "${hsm_ip_address}"
/opt/cloudhsm/bin/cloudhsm_client /opt/cloudhsm/etc/cloudhsm_client.cfg > cloudhsm.log 2>&1 &
cd /integration_tests
gem install bundler
bundle install
bundle exec cucumber features/feature/
bash
