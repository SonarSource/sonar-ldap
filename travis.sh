#!/bin/bash

set -euo pipefail

function installTravisTools {
  curl -sSL https://raw.githubusercontent.com/sonarsource/travis-utils/v13/install.sh | bash
  source /tmp/travis-utils/env.sh
}

case "$TESTS" in

CI)
  mvn verify -B -e -V
  ;;

IT-DEV)
  installTravisTools
  travis_start_xvfb

  mvn install -Dsource.skip=true -Denforcer.skip=true -Danimal.sniffer.skip=true -Dmaven.test.skip=true

  travis_build_green "SonarSource/sonarqube" "master"

  cd it
  mvn -DldapVersion="DEV" -Dsonar.runtimeVersion="DEV" -Dmaven.test.redirectTestOutputToFile=false install
  ;;

IT-LTS)
  installTravisTools
  travis_start_xvfb

  mvn install -Dsource.skip=true -Denforcer.skip=true -Danimal.sniffer.skip=true -Dmaven.test.skip=true

  travis_download_sonarqube_release "4.5.1"

  cd it
  mvn -DldapVersion="DEV" -Dsonar.runtimeVersion="4.5.1" -Dmaven.test.redirectTestOutputToFile=false install
  ;;

esac
