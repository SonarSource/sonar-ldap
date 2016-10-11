SonarQube LDAP Plugin
=====================
[![SonarQube.Com Quality Gate status](https://sonarqube.com/api/badges/gate?key=org.sonarsource.ldap%3Asonar-ldap-plugin)](https://sonarqube.com/overview?id=org.sonarsource.ldap%3Asonar-ldap-plugin)

For more, see [the docs](http://docs.sonarqube.org/display/PLUG/LDAP+Plugin)


## Example

You can check this plugin in action using Docker as described below.

Build plugin:

    mvn clean package

Generate certificates:

    ./docker/gen-certs.sh

Build containers (SonarQube and OpenLDAP servers):

    docker-compose build

Start containers:

    docker-compose up

To access SonarQube use LDAP user `tester` with password `test`.
