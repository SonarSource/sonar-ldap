/*
 * Sonar LDAP Plugin
 * Copyright (C) 2009 SonarSource
 * dev@sonar.codehaus.org
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

import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.sonar.api.config.Settings;
import org.sonar.plugins.ldap.server.LdapServer;

import java.util.Map;

import static org.fest.assertions.Assertions.assertThat;

public class LdapAuthenticatorTest {

    @ClassRule
    public static LdapServer exampleServer = new LdapServer("/users.example.org.ldif");
    @Rule
    public static LdapServer infosupportServer = new LdapServer("/users.infosupport.com.ldif","infosupport.com","dc=infosupport,dc=com");

  @Test
  public void testNoConnection() {
    exampleServer.disableAnonymousAccess();
    try {
      Map<String, LdapContextFactory> contextFactories = LdapContextFactories.createForAnonymousAccess(exampleServer.getUrl());
      Map<String, LdapUserMapping> userMappings = createMapping();
      LdapAuthenticator authenticator = new LdapAuthenticator(contextFactories, userMappings);
      authenticator.authenticate("godin", "secret1");
    } finally {
      exampleServer.enableAnonymousAccess();
    }
  }

  @Test
  public void testSimple() {
    Map<String, LdapContextFactory> contextFactories = LdapContextFactories.createForAnonymousAccess(exampleServer.getUrl());
    Map<String, LdapUserMapping> userMappings = createMapping();
    LdapAuthenticator authenticator = new LdapAuthenticator(contextFactories, userMappings);

    assertThat(authenticator.authenticate("godin", "secret1")).isTrue();
    assertThat(authenticator.authenticate("godin", "wrong")).isFalse();

    assertThat(authenticator.authenticate("tester", "secret2")).isTrue();
    assertThat(authenticator.authenticate("tester", "wrong")).isFalse();

    assertThat(authenticator.authenticate("notfound", "wrong")).isFalse();
    // SONARPLUGINS-2493
    assertThat(authenticator.authenticate("godin", "")).isFalse();
    assertThat(authenticator.authenticate("godin", null)).isFalse();
  }
    public void testSimpleMultiLdap(){
        LdapSettingsManager settingsManager = new LdapSettingsManager(LdapSettingsFactory.SIMPLEANONYMOUSACCESS);
        LdapAuthenticator authenticator = new LdapAuthenticator(settingsManager.getContextFactories(), settingsManager.getUserMappings());

        assertThat(authenticator.authenticate("godin", "secret1")).isTrue();
        assertThat(authenticator.authenticate("godin", "wrong")).isFalse();

        assertThat(authenticator.authenticate("tester", "secret2")).isTrue();
        assertThat(authenticator.authenticate("tester", "wrong")).isFalse();

        assertThat(authenticator.authenticate("notfound", "wrong")).isFalse();
        // SONARPLUGINS-2493
        assertThat(authenticator.authenticate("godin", "")).isFalse();
        assertThat(authenticator.authenticate("godin", null)).isFalse();

        // SONARPLUGINS-2793
        assertThat(authenticator.authenticate("robby", "secret1")).isTrue();
        assertThat(authenticator.authenticate("robby", "wrong")).isFalse();
    }

  @Test
  public void testSasl() {
    Map<String, LdapContextFactory> contextFactories =
        LdapContextFactories.createForAuthenticationMethod(exampleServer.getUrl(), LdapContextFactory.CRAM_MD5_METHOD, "example.org", "bind", "bindpassword");
    Map<String, LdapUserMapping> userMappings = createMapping();
    LdapAuthenticator authenticator = new LdapAuthenticator(contextFactories, userMappings);

    assertThat(authenticator.authenticate("godin", "secret1")).isTrue();
    assertThat(authenticator.authenticate("godin", "wrong")).isFalse();

    assertThat(authenticator.authenticate("tester", "secret2")).isTrue();
    assertThat(authenticator.authenticate("tester", "wrong")).isFalse();

    assertThat(authenticator.authenticate("notfound", "wrong")).isFalse();
  }
    @Test
    public void testSaslMultipleLdap(){
        LdapSettingsManager settingsManager = new LdapSettingsManager(LdapSettingsFactory.generateAuthenticationSettings(exampleServer,infosupportServer));
        LdapAuthenticator authenticator = new LdapAuthenticator(settingsManager.getContextFactories(), settingsManager.getUserMappings());

        assertThat(authenticator.authenticate("godin", "secret1")).isTrue();
        assertThat(authenticator.authenticate("godin", "wrong")).isFalse();

        assertThat(authenticator.authenticate("tester", "secret2")).isTrue();
        assertThat(authenticator.authenticate("tester", "wrong")).isFalse();

        assertThat(authenticator.authenticate("notfound", "wrong")).isFalse();

        assertThat(authenticator.authenticate("robby", "secret1")).isTrue();
        assertThat(authenticator.authenticate("robby", "wrong")).isFalse();
    }

  private static Map<String, LdapUserMapping> createMapping() {
    Settings settings = new Settings()
        .setProperty("ldap.user.baseDn", "ou=users,dc=example,dc=org");
      LdapSettingsManager settingsManager = new LdapSettingsManager(settings);
    return settingsManager.getUserMappings();
  }

}
