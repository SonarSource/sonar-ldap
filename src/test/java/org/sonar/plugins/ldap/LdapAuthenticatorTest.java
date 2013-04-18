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
import org.junit.Test;
import org.sonar.api.config.Settings;
import org.sonar.plugins.ldap.server.LdapServer;

import java.util.Map;

import static org.fest.assertions.Assertions.assertThat;

public class LdapAuthenticatorTest {

  @ClassRule
  public static LdapServer server = new LdapServer("/users.example.org.ldif");

  @Test
  public void testNoConnection() {
    server.disableAnonymousAccess();
    try {
      Map<String, LdapContextFactory> contextFactories = LdapContextFactories.createForAnonymousAccess(server.getUrl());
      Map<String, LdapUserMapping> userMappings = createMapping();
      LdapAuthenticator authenticator = new LdapAuthenticator(contextFactories, userMappings);
      authenticator.authenticate("godin", "secret1");
    } finally {
      server.enableAnonymousAccess();
    }
  }

  @Test
  public void testSimple() {
    Map<String, LdapContextFactory> contextFactories = LdapContextFactories.createForAnonymousAccess(server.getUrl());
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

    //TODO: SONARPLUGINS-2793
    //assertThat(authenticator.authenticate("robby", "secret1")).isTrue();
    //assertThat(authenticator.authenticate("robby", "wrong")).isFalse();
  }
    public void testSimpleMultiLdap(){
        //TODO: check if authentication against multiple ldap servers works.
    }

  @Test
  public void testSasl() {
    Map<String, LdapContextFactory> contextFactories =
        LdapContextFactories.createForAuthenticationMethod(server.getUrl(), LdapContextFactory.CRAM_MD5_METHOD, "example.org", "bind", "bindpassword");
    Map<String, LdapUserMapping> userMappings = createMapping();
    LdapAuthenticator authenticator = new LdapAuthenticator(contextFactories, userMappings);

    assertThat(authenticator.authenticate("godin", "secret1")).isTrue();
    assertThat(authenticator.authenticate("godin", "wrong")).isFalse();

    assertThat(authenticator.authenticate("tester", "secret2")).isTrue();
    assertThat(authenticator.authenticate("tester", "wrong")).isFalse();

    assertThat(authenticator.authenticate("notfound", "wrong")).isFalse();
  }

  private static Map<String, LdapUserMapping> createMapping() {
    Settings settings = new Settings()
        .setProperty("ldap.user.baseDn", "ou=users,dc=example,dc=org");
      LdapSettingsManager settingsManager = new LdapSettingsManager(settings);
    return settingsManager.getUserMappings();
  }

}
