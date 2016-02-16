/*
 * SonarQube LDAP Plugin :: Integration Tests
 * Copyright (C) 2009 SonarSource
 * sonarqube@googlegroups.com
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
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02
 */
package org.sonarsource.ldap.it;

import com.google.common.base.Objects;
import com.google.common.base.Preconditions;
import com.sonar.orchestrator.Orchestrator;
import com.sonar.orchestrator.OrchestratorBuilder;
import com.sonar.orchestrator.selenium.Selenese;
import org.junit.After;
import org.junit.Test;
import org.sonar.wsclient.Host;
import org.sonar.wsclient.Sonar;
import org.sonar.wsclient.connectors.ConnectionException;
import org.sonar.wsclient.connectors.HttpClient4Connector;
import org.sonar.wsclient.services.PropertyUpdateQuery;
import org.sonar.wsclient.services.UserPropertyCreateQuery;
import org.sonar.wsclient.services.UserPropertyQuery;
import org.sonar.wsclient.user.UserParameters;

import static java.lang.String.format;
import static org.assertj.core.api.Assertions.assertThat;

public class LdapTest extends AbstractTest {

  private static final String BASE_DN = "dc=sonarsource,dc=com";

  private static ApacheDS ldapServer;
  private static Orchestrator orchestrator;

  private static void start(boolean savePasswords, boolean syncGroups) {
    // Start LDAP server
    try {
      ldapServer = ApacheDS.start(BASE_DN, "target/ldap-work");
    } catch (Exception e) {
      throw new RuntimeException("Unable to start LDAP server", e);
    }
    importLdif("init");

    // Start Sonar with LDAP plugin
    OrchestratorBuilder orchestratorBuilder = Orchestrator.builderEnv()
      .setContext("/")
      .addPlugin(ldapPluginLocation())
      .setMainPluginKey("ldap")
      .setServerProperty("sonar.security.savePassword", Boolean.toString(savePasswords))
      // enable ldap
      .setServerProperty("sonar.security.realm", "LDAP")
      .setServerProperty("ldap.url", ldapServer.getUrl())
      // users mapping
      .setServerProperty("ldap.user.baseDn", "ou=people," + BASE_DN);

    if (syncGroups) {
      orchestratorBuilder
        // groups mapping
        .setServerProperty("ldap.group.baseDn", "ou=groups," + BASE_DN)
        .setServerProperty("ldap.group.memberFormat", "uid=$username,ou=people," + BASE_DN)
        .build();
    }

    orchestrator = orchestratorBuilder.build();
    orchestrator.start();
  }

  @After
  public void stop() {
    if (orchestrator != null) {
      orchestrator.stop();
      orchestrator = null;
    }
    if (ldapServer != null) {
      try {
        ldapServer.stop();
      } catch (Exception e) {
        throw new RuntimeException("Unable to stop LDAP server", e);
      }
      ldapServer = null;
    }
  }

  /**
   * SONARPLUGINS-895, SONARPLUGINS-1311
   */
  @Test
  public void test() throws Exception {
    start(true, true);

    // When user exists in Sonar, but not in LDAP (technical account)
    // Then can login because admin is technical account by default
    assertThat(loginAttempt("admin", "admin")).as("admin available in Sonar, even if not available in LDAP").isEqualTo(AUTHORIZED);
    executeSelenese("admin-available");
    if (orchestrator.getServer().version().isGreaterThanOrEquals("4.2")) {
      orchestrator.getServer().adminWsClient().userClient().create(UserParameters.create().login("admin2").name("Admin2").password("foobar").passwordConfirmation("foobar"));
      assertThat(loginAttempt("admin2", "foobar")).as("admin2 available in Sonar, but not available in LDAP and not a local user").isEqualTo(NOT_AUTHORIZED);
      // Add admin2 to the list of local users
      orchestrator.getServer().getAdminWsClient().update(new PropertyUpdateQuery("sonar.security.localUsers", "admin,admin2"));
      assertThat(loginAttempt("admin2", "foobar")).as("admin2 available in Sonar, not available in LDAP but is a local user").isEqualTo(AUTHORIZED);
    }

    // When user not exists in Sonar and in LDAP
    // Then can not login
    assertThat(loginAttempt("godin", "12345")).as("User not created in Sonar").isEqualTo(NOT_AUTHORIZED);

    // Verify that we can't login with blank password (SONARPLUGINS-2493)
    assertThat(loginAttempt("godin", "")).as("Blank password doens't allow to login").isEqualTo(NOT_AUTHORIZED);

    // When user created in LDAP
    importLdif("add-user");
    // Then user created in Sonar with details from LDAP
    assertThat(loginAttempt("godin", "12345")).as("User created in Sonar").isEqualTo(AUTHORIZED);
    executeSelenese("user-created");

    // When new password set in LDAP
    importLdif("change-password");
    // Then new password works in Sonar, but not old password
    assertThat(loginAttempt("godin", "54321")).as("New password works in Sonar").isEqualTo(AUTHORIZED);
    assertThat(loginAttempt("godin", "12345")).as("Old password does not work in Sonar").isEqualTo(NOT_AUTHORIZED);
    executeSelenese("password-changed");

    // When user was modified in LDAP, but LDAP not available
    importLdif("change-details");
    ldapServer.disableAnonymousAccess();
    // Then old details available in Sonar and latest password works (because sonar.security.savePassword=true), but not previous
    assertThat(loginAttempt("godin", "54321")).as("New password works in Sonar").isEqualTo(AUTHORIZED);
    assertThat(loginAttempt("godin", "12345")).as("Old password does not work in Sonar").isEqualTo(NOT_AUTHORIZED);
    executeSelenese("password-changed");

    // When LDAP available again
    ldapServer.enableAnonymousAccess();
    // Then new details (email, groups) available in Sonar
    executeSelenese("details-changed");
  }

  /**
   * SONARPLUGINS-2493
   */
  @Test
  public void blank_passwords_are_forbidden() throws Exception {
    start(true, true);

    importLdif("add-user-without-password");

    assertThat(loginAttempt("gerard", "")).as("Blank password doens't allow to login").isEqualTo(NOT_AUTHORIZED);
  }

  /**
   * SONARPLUGINS-895, SONARPLUGINS-1311
   */
  @Test
  public void test2() throws Exception {
    start(false, true);

    // When user exists in Sonar, but not in LDAP
    // Then can login
    assertThat(loginAttempt("admin", "admin")).as("admin available in Sonar, even if not available in LDAP").isEqualTo(AUTHORIZED);
    executeSelenese("admin-available");

    // When user not exists in Sonar and in LDAP
    // Then can not login
    assertThat(loginAttempt("godin", "12345")).as("User not created in Sonar").isEqualTo(NOT_AUTHORIZED);

    // When user created in LDAP
    importLdif("add-user");
    // Then user created in Sonar with details from LDAP
    assertThat(loginAttempt("godin", "12345")).as("User created in Sonar").isEqualTo(AUTHORIZED);
    executeSelenese("user-created");

    // When new password set in LDAP
    importLdif("change-password");
    // Then new password works in Sonar, but not old password
    assertThat(loginAttempt("godin", "54321")).as("New password works in Sonar").isEqualTo(AUTHORIZED);
    assertThat(loginAttempt("godin", "12345")).as("Old password does not work in Sonar").isEqualTo(NOT_AUTHORIZED);
    executeSelenese("password-changed");

    // When user was modified in LDAP, but LDAP not available
    importLdif("change-details");
    ldapServer.disableAnonymousAccess();
    // Then user can't login (because sonar.security.savePassword=false)
    assertThat(loginAttempt("godin", "54321")).as("New password does not work in Sonar").isEqualTo(NOT_AUTHORIZED);

    // When LDAP available again
    ldapServer.enableAnonymousAccess();
    // Then new details (email, groups) available in Sonar
    executeSelenese("details-changed");
  }

  /**
   * SONARPLUGINS-1845
   */
  @Test
  public void deactivate_group_synchronization() {
    start(false, false);

    // When user created in LDAP
    importLdif("add-user");
    // Then user created in Sonar with details from LDAP
    assertThat(loginAttempt("godin", "12345")).as("User created in Sonar").isEqualTo(AUTHORIZED);
    // But without synchronization of groups
    executeSelenese("user-created-without-groups-sync");
  }

  private static void importLdif(String ldifName) {
    String resourceName = format("/ldif/%s.ldif", ldifName);
    try {
      ldapServer.importLdif(LdapTest.class.getResourceAsStream(resourceName));
    } catch (Exception e) {
      throw new RuntimeException("Unable to import LDIF(" + resourceName + "): " + e.getMessage(), e);
    }
  }

  private static void executeSelenese(String name) {
    orchestrator.executeSelenese(Selenese.builder().setHtmlTestsInClasspath("ldap-" + name, format("/selenium/%s.html", name)).build());
  }

  private static String AUTHORIZED = "authorized";
  private static String NOT_AUTHORIZED = "not authorized";

  /**
   * Utility method to check that user can be authorized.
   *
   * @throws IllegalStateException
   */
  private static String loginAttempt(String username, String password) {
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
  private static Sonar createWsClient(String username, String password) {
    Preconditions.checkNotNull(username);
    Preconditions.checkNotNull(password);
    return new Sonar(new HttpClient4Connector(new Host(orchestrator.getServer().getUrl(), username, password)));
  }

}
