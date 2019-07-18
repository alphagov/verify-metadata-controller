#!/bin/bash
cp ../build/distributions/mdgen.zip ./
cp -f ../test/* ./test/
docker run -it -e HSM_USER -e HSM_PASSWORD -v $(pwd)/test:/test -v $(pwd)/mdgen.zip:/mdgen.zip --mount src=$(pwd)/integration_tests,target=/integration_tests,type=bind mdgen:docker
rm -fr ./mdgen
rm mdgen.zip