#!/bin/bash

set -euo pipefail

function configureTravis {
  mkdir ~/.local
  curl -sSL https://github.com/SonarSource/travis-utils/tarball/v28 | tar zx --strip-components 1 -C ~/.local
  source ~/.local/bin/install
}
configureTravis

# for Selenium tests
start_xvfb

export DEPLOY_PULL_REQUEST=true

regular_mvn_build_deploy_analyze

MIN_SQ_VERSION="5.6-RC2"
echo '======= Run integration tests on minimal supported version of SonarQube ($MIN_SQ_VERSION)'
./run-integration-tests.sh "$MIN_SQ_VERSION"
# all other versions of SQ are tested by the QA pipeline at SonarSource
