/*
 * SonarQube LDAP Plugin :: Integration Tests
 * Copyright (C) 2009-2016 SonarSource SA
 * mailto:contact AT sonarsource DOT com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
package org.sonarsource.ldap.it;

import com.google.common.base.Objects;
import com.google.common.base.Preconditions;
import com.sonar.orchestrator.Orchestrator;
import com.sonar.orchestrator.OrchestratorBuilder;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.sonar.wsclient.Host;
import org.sonar.wsclient.Sonar;
import org.sonar.wsclient.connectors.ConnectionException;
import org.sonar.wsclient.connectors.HttpClient4Connector;
import org.sonar.wsclient.services.UserPropertyCreateQuery;
import org.sonar.wsclient.services.UserPropertyQuery;

import static org.assertj.core.api.Assertions.assertThat;

public class MultipleLdapTest extends AbstractTest {

  private static final String BASE_DN1 = "dc=example,dc=org";
  private static final String BASE_DN2 = "dc=infosupport,dc=com";

  private ApacheDS ldapServer1;
  private ApacheDS ldapServer2;
  private Orchestrator orchestrator;

  @Before
  public void start() {
    OrchestratorBuilder orchestratorBuilder = Orchestrator.builderEnv()
      .addPlugin(ldapPluginLocation())
      .setMainPluginKey("ldap")
      .setContext("/");

    // Start LDAP server
    try {
      ldapServer1 = ApacheDS.start(BASE_DN1, "target/ldap1-work");
      ldapServer2 = ApacheDS.start(BASE_DN2, "target/ldap2-work");
    } catch (Exception e) {
      throw new RuntimeException("Unable to start LDAP server", e);
    }
    importLdif(ldapServer1, "users.example.org");
    importLdif(ldapServer2, "users.infosupport.com");

    // Start Sonar with LDAP plugin
    orchestratorBuilder.setServerProperty("sonar.security.savePassword", "true")
      // enable ldap
      .setServerProperty("sonar.security.realm", "LDAP")
      .setServerProperty("ldap.servers", "example,infosupport")
      .setServerProperty("ldap.example.url", ldapServer1.getUrl())
      .setServerProperty("ldap.infosupport.url", ldapServer2.getUrl())
      // users mapping
      .setServerProperty("ldap.example.user.baseDn", "ou=users," + BASE_DN1)
      .setServerProperty("ldap.infosupport.user.baseDn", "ou=users," + BASE_DN2)
      // groups mapping
      .setServerProperty("ldap.example.group.baseDn", "ou=groups," + BASE_DN1)
      .setServerProperty("ldap.infosupport.group.baseDn", "ou=groups," + BASE_DN2)
      .build();

    orchestrator = orchestratorBuilder.build();
    orchestrator.start();
  }

  @After
  public void stop() {
    if (orchestrator != null) {
      orchestrator.stop();
      orchestrator = null;
    }
    if (ldapServer1 != null) {
      try {
        ldapServer1.stop();
      } catch (Exception e) {
        throw new RuntimeException("Unable to stop LDAP server", e);
      } finally {
        ldapServer1 = null;
        if (ldapServer2 != null) {
          try {
            ldapServer2.stop();
          } catch (Exception e) {
            throw new RuntimeException("Unable to stop LDAP server", e);
          }
          ldapServer2 = null;
        }
      }
    }
  }

  /**
   * SONARPLUGINS-2793
   */
  @Test
  public void testLoginOnMultipleServers() throws Exception {
    assertThat(loginAttempt("godin", "secret1")).as("Unable to login with user in first server").isEqualTo(AUTHORIZED);
    assertThat(loginAttempt("robby", "secret1")).as("Unable to login with user in second server").isEqualTo(AUTHORIZED);
    // Same user with different password in server 2
    assertThat(loginAttempt("godin", "secret2")).as("Unable to login with user in second server").isEqualTo(AUTHORIZED);

    assertThat(loginAttempt("godin", "12345")).as("Should not allow login with wrong password").isEqualTo(NOT_AUTHORIZED);
    assertThat(loginAttempt("foo", "12345")).as("Should not allow login with unknow user").isEqualTo(NOT_AUTHORIZED);
  }

  private static void importLdif(ApacheDS server, String ldifName) {
    String resourceName = "/ldif/" + ldifName + ".ldif";
    try {
      server.importLdif(MultipleLdapTest.class.getResourceAsStream(resourceName));
    } catch (Exception e) {
      throw new RuntimeException("Unable to import LDIF(" + resourceName + "): " + e.getMessage(), e);
    }
  }

  private static String AUTHORIZED = "authorized";
  private static String NOT_AUTHORIZED = "not authorized";

  /**
   * Utility method to check that user can be authorized.
   *
   * @throws IllegalStateException
   */
  private String loginAttempt(String username, String password) {
    String expectedValue = Long.toString(System.currentTimeMillis());
    Sonar wsClient = createWsClient(username, password);
    try {
      wsClient.create(new UserPropertyCreateQuery("auth", expectedValue));
    } catch (ConnectionException e) {
      return NOT_AUTHORIZED;
    }
    try {
      String value = wsClient.find(new UserPropertyQuery("auth")).getValue();
      if (!Objects.equal(value, expectedValue)) {
        // exceptional case - update+retrieval were successful, but value doesn't match
        throw new IllegalStateException("Expected " + expectedValue + " , but got " + value);
      }
    } catch (ConnectionException e) {
      // exceptional case - update was successful, but not retrieval
      throw new IllegalStateException(e);
    }
    return AUTHORIZED;
  }

  /**
   * Utility method to create {@link org.sonar.wsclient.Sonar} with specified {@code username} and {@code password}.
   * Orchestrator does not provide such method.
   */
  private Sonar createWsClient(String username, String password) {
    Preconditions.checkNotNull(username);
    Preconditions.checkNotNull(password);
    return new Sonar(new HttpClient4Connector(new Host(orchestrator.getServer().getUrl(), username, password)));
  }

}
