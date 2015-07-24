#!/bin/bash

set -euo pipefail

function installTravisTools {
  mkdir ~/.local
  curl -sSL https://github.com/SonarSource/travis-utils/tarball/v15 | tar zx --strip-components 1 -C ~/.local
  source ~/.local/bin/install
}

case "$TESTS" in

CI)
  mvn verify -B -e -V
  ;;

IT-DEV)
  installTravisTools
  start_xvfb

  mvn install -Dsource.skip=true -Denforcer.skip=true -Danimal.sniffer.skip=true -Dmaven.test.skip=true

  build_snapshot "SonarSource/sonarqube"

  cd it
  mvn -DldapVersion="DEV" -Dsonar.runtimeVersion="DEV" -Dmaven.test.redirectTestOutputToFile=false install
  ;;

IT-LTS)
  installTravisTools
  start_xvfb

  mvn install -Dsource.skip=true -Denforcer.skip=true -Danimal.sniffer.skip=true -Dmaven.test.skip=true

  cd it
  mvn -DldapVersion="DEV" -Dsonar.runtimeVersion="4.5.1" -Dmaven.test.redirectTestOutputToFile=false install
  ;;

esac
