#!/bin/bash
export LD_LIBRARY_PATH=/opt/cloudhsm/lib
export HSM_PARTITION=PARTITION_1
/opt/cloudhsm/bin/cloudhsm_client /opt/cloudhsm/etc/cloudhsm_client.cfg > cloudhsm.log 2>&1 &
cd /integration_tests
gem install bundler
bundle install
bundle exec cucumber features/feature/
bash
