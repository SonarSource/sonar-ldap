/*
 * SonarQube LDAP Plugin
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
package org.sonar.plugins.ldap;

import javax.servlet.http.HttpServletRequest;
import org.junit.ClassRule;
import org.junit.Test;
import org.mockito.Mockito;
import org.sonar.api.config.Settings;
import org.sonar.api.security.Authenticator;
import org.sonar.plugins.ldap.server.LdapServer;

import static org.assertj.core.api.Assertions.assertThat;

public class LdapAuthenticatorTest {

  /**
   * A reference to the original ldif file
   */
  public static final String USERS_EXAMPLE_ORG_LDIF = "/users.example.org.ldif";
  /**
   * A reference to an additional ldif file.
   */
  public static final String USERS_INFO_SUPPORT_COM_LDIF = "/users.infosupport.com.ldif";
  @ClassRule
  public static LdapServer exampleServer = new LdapServer(USERS_EXAMPLE_ORG_LDIF);
  @ClassRule
  public static LdapServer infoSupportServer = new LdapServer(USERS_INFO_SUPPORT_COM_LDIF, "infosupport.com", "dc=infosupport,dc=com");

  @Test
  public void testNoConnection() {
    exampleServer.disableAnonymousAccess();
    try {
      LdapAuthenticator authenticator = getLdapAuthenticator(exampleServer, null);
      runDoAuthenticate(authenticator, "godin", "secret1");
    } finally {
      exampleServer.enableAnonymousAccess();
    }
  }

  @Test
  public void testSimple() {
    LdapAuthenticator authenticator = getLdapAuthenticator(exampleServer, null);

    assertThat(runDoAuthenticate(authenticator, "godin", "secret1")).isTrue();
    assertThat(runDoAuthenticate(authenticator, "godin", "wrong")).isFalse();

    assertThat(runDoAuthenticate(authenticator, "tester", "secret2")).isTrue();
    assertThat(runDoAuthenticate(authenticator, "tester", "wrong")).isFalse();

    assertThat(runDoAuthenticate(authenticator, "notfound", "wrong")).isFalse();
    // SONARPLUGINS-2493
    assertThat(runDoAuthenticate(authenticator, "godin", "")).isFalse();
    assertThat(runDoAuthenticate(authenticator, "godin", null)).isFalse();
  }

  @Test
  public void testSimpleMultiLdap() {
    LdapAuthenticator authenticator = getLdapAuthenticator(exampleServer, infoSupportServer);

    assertThat(runDoAuthenticate(authenticator, "godin", "secret1")).isTrue();
    assertThat(runDoAuthenticate(authenticator, "godin", "wrong")).isFalse();

    assertThat(runDoAuthenticate(authenticator, "tester", "secret2")).isTrue();
    assertThat(runDoAuthenticate(authenticator, "tester", "wrong")).isFalse();

    assertThat(runDoAuthenticate(authenticator, "notfound", "wrong")).isFalse();
    // SONARPLUGINS-2493
    assertThat(runDoAuthenticate(authenticator, "godin", "")).isFalse();
    assertThat(runDoAuthenticate(authenticator, "godin", null)).isFalse();

    // SONARPLUGINS-2793
    assertThat(runDoAuthenticate(authenticator, "robby", "secret1")).isTrue();
    assertThat(runDoAuthenticate(authenticator, "robby", "wrong")).isFalse();
  }

  @Test
  public void testSasl() {
    LdapAuthenticator authenticator = getLdapAuthenticator(exampleServer, null);

    assertThat(runDoAuthenticate(authenticator, "godin", "secret1")).isTrue();
    assertThat(runDoAuthenticate(authenticator, "godin", "wrong")).isFalse();

    assertThat(runDoAuthenticate(authenticator, "tester", "secret2")).isTrue();
    assertThat(runDoAuthenticate(authenticator, "tester", "wrong")).isFalse();

    assertThat(runDoAuthenticate(authenticator, "notfound", "wrong")).isFalse();
  }

  @Test
  public void testSaslMultipleLdap() {
    LdapAuthenticator authenticator = getLdapAuthenticator(exampleServer, infoSupportServer);

    assertThat(runDoAuthenticate(authenticator, "godin", "secret1")).isTrue();
    assertThat(runDoAuthenticate(authenticator, "godin", "wrong")).isFalse();

    assertThat(runDoAuthenticate(authenticator, "tester", "secret2")).isTrue();
    assertThat(runDoAuthenticate(authenticator, "tester", "wrong")).isFalse();

    assertThat(runDoAuthenticate(authenticator, "notfound", "wrong")).isFalse();

    assertThat(runDoAuthenticate(authenticator, "robby", "secret1")).isTrue();
    assertThat(runDoAuthenticate(authenticator, "robby", "wrong")).isFalse();
  }

  private static LdapAuthenticator getLdapAuthenticator(LdapServer exampleServer, LdapServer infoSupportServer) {
    Settings settings = LdapSettingsFactory.generateAuthenticationSettings(exampleServer, infoSupportServer);
    LdapSettingsManager settingsManager = new LdapSettingsManager(new LdapSettings(settings), new LdapAutodiscovery());

    return new LdapAuthenticator(settingsManager.getContextFactories(), settingsManager.getUserMappings());
  }

  private static boolean runDoAuthenticate(Authenticator authenticator, String userName, String password) {
    return authenticator.doAuthenticate(new Authenticator.Context(userName, password, Mockito.mock(HttpServletRequest.class)));
  }

}
