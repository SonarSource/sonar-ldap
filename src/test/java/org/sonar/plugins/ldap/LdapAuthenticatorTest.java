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

import static org.fest.assertions.Assertions.assertThat;

public class LdapAuthenticatorTest {

  @ClassRule
  public static LdapServer server = new LdapServer("/users.ldif");

  @Test
  public void testNoConnection() {
    server.disableAnonymousAccess();
    try {
      LdapContextFactory contextFactory = LdapContextFactories.createForAnonymousAccess(server.getUrl());
      LdapUserMapping userMapping = createMapping();
      LdapAuthenticator authenticator = new LdapAuthenticator(contextFactory, userMapping);
      authenticator.authenticate("godin", "secret1");
    } finally {
      server.enableAnonymousAccess();
    }
  }

  @Test
  public void testSimple() {
    LdapContextFactory contextFactory = LdapContextFactories.createForAnonymousAccess(server.getUrl());
    LdapUserMapping userMapping = createMapping();
    LdapAuthenticator authenticator = new LdapAuthenticator(contextFactory, userMapping);

    assertThat(authenticator.authenticate("godin", "secret1")).isTrue();
    assertThat(authenticator.authenticate("godin", "wrong")).isFalse();

    assertThat(authenticator.authenticate("tester", "secret2")).isTrue();
    assertThat(authenticator.authenticate("tester", "wrong")).isFalse();

    assertThat(authenticator.authenticate("notfound", "wrong")).isFalse();
    // SONARPLUGINS-2493
    assertThat(authenticator.authenticate("godin", "")).isFalse();
    assertThat(authenticator.authenticate("godin", null)).isFalse();
  }

  @Test
  public void testSasl() {
    LdapContextFactory contextFactory =
        LdapContextFactories.createForAuthenticationMethod(server.getUrl(), LdapContextFactory.CRAM_MD5_METHOD, "example.org", "bind", "bindpassword");
    LdapUserMapping userMapping = createMapping();
    LdapAuthenticator authenticator = new LdapAuthenticator(contextFactory, userMapping);

    assertThat(authenticator.authenticate("godin", "secret1")).isTrue();
    assertThat(authenticator.authenticate("godin", "wrong")).isFalse();

    assertThat(authenticator.authenticate("tester", "secret2")).isTrue();
    assertThat(authenticator.authenticate("tester", "wrong")).isFalse();

    assertThat(authenticator.authenticate("notfound", "wrong")).isFalse();
  }

  private static LdapUserMapping createMapping() {
    Settings settings = new Settings()
        .setProperty("ldap.user.baseDn", "ou=users,dc=example,dc=org");
    return new LdapUserMapping(settings);
  }

}
