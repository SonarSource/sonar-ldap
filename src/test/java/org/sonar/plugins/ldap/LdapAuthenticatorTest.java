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

import javax.servlet.http.HttpServletRequest;

import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;
import org.mockito.Mockito;
import org.sonar.api.config.Settings;
import org.sonar.api.security.Authenticator.Context;
import org.sonar.plugins.ldap.server.LdapServer;

import static org.fest.assertions.Assertions.assertThat;

public class LdapAuthenticatorTest {

  private HttpServletRequest request;
  /**
   * A reference to the original ldif file
   */
  public static final String USERS_EXAMPLE_ORG_LDIF = "/users.example.org.ldif";
  /**
   * A reference to an aditional ldif file.
   */
  public static final String USERS_INFOSUPPORT_COM_LDIF = "/users.infosupport.com.ldif";
  @ClassRule
  public static LdapServer exampleServer = new LdapServer(USERS_EXAMPLE_ORG_LDIF);
  @ClassRule
  public static LdapServer infosupportServer = new LdapServer(USERS_INFOSUPPORT_COM_LDIF, "infosupport.com", "dc=infosupport,dc=com");

  @Before
  public void setup() {
    request = Mockito.mock(HttpServletRequest.class);
  }
  
  @Test
  public void testNoConnection() {
    exampleServer.disableAnonymousAccess();
    try {
      LdapSettingsManager settingsManager = new LdapSettingsManager(LdapSettingsFactory.generateAuthenticationSettings(exampleServer, null));
      LdapAuthenticator authenticator = new LdapAuthenticator(settingsManager.getContextFactories(), settingsManager.getUserMappings());
      authenticator.doAuthenticate(new Context("godin", "secret1", request));
    } finally {
      exampleServer.enableAnonymousAccess();
    }
  }

  @Test
  public void testSimple() {
    LdapSettingsManager settingsManager = new LdapSettingsManager(LdapSettingsFactory.generateAuthenticationSettings(exampleServer, null));
    LdapAuthenticator authenticator = new LdapAuthenticator(settingsManager.getContextFactories(), settingsManager.getUserMappings());

    assertThat(authenticator.doAuthenticate(new Context("godin", "secret1", request))).isTrue();
    assertThat(authenticator.doAuthenticate(new Context("godin", "wrong", request))).isFalse();

    assertThat(authenticator.doAuthenticate(new Context("tester", "secret2", request))).isTrue();
    assertThat(authenticator.doAuthenticate(new Context("tester", "wrong", request))).isFalse();

    assertThat(authenticator.doAuthenticate(new Context("notfound", "wrong", request))).isFalse();
    // SONARPLUGINS-2493
    assertThat(authenticator.doAuthenticate(new Context("godin", "", request))).isFalse();
    assertThat(authenticator.doAuthenticate(new Context("godin", null, request))).isFalse();
  }

  @Test
  public void testSimpleMultiLdap() {
    LdapSettingsManager settingsManager = new LdapSettingsManager(LdapSettingsFactory.generateAuthenticationSettings(exampleServer, infosupportServer));
    LdapAuthenticator authenticator = new LdapAuthenticator(settingsManager.getContextFactories(), settingsManager.getUserMappings());

    assertThat(authenticator.doAuthenticate(new Context("godin", "secret1", request))).isTrue();
    assertThat(authenticator.doAuthenticate(new Context("godin", "wrong", request))).isFalse();

    assertThat(authenticator.doAuthenticate(new Context("tester", "secret2", request))).isTrue();
    assertThat(authenticator.doAuthenticate(new Context("tester", "wrong", request))).isFalse();

    assertThat(authenticator.doAuthenticate(new Context("notfound", "wrong", request))).isFalse();
    // SONARPLUGINS-2493
    assertThat(authenticator.doAuthenticate(new Context("godin", "", request))).isFalse();
    assertThat(authenticator.doAuthenticate(new Context("godin", null, request))).isFalse();

    // SONARPLUGINS-2793
    assertThat(authenticator.doAuthenticate(new Context("robby", "secret1", request))).isTrue();
    assertThat(authenticator.doAuthenticate(new Context("robby", "wrong", request))).isFalse();
  }

  @Test
  public void testSasl() {
    LdapSettingsManager settingsManager = new LdapSettingsManager(LdapSettingsFactory.generateAuthenticationSettings(exampleServer, null));
    LdapAuthenticator authenticator = new LdapAuthenticator(settingsManager.getContextFactories(), settingsManager.getUserMappings());

    assertThat(authenticator.doAuthenticate(new Context("godin", "secret1", request))).isTrue();
    assertThat(authenticator.doAuthenticate(new Context("godin", "wrong", request))).isFalse();

    assertThat(authenticator.doAuthenticate(new Context("tester", "secret2", request))).isTrue();
    assertThat(authenticator.doAuthenticate(new Context("tester", "wrong", request))).isFalse();

    assertThat(authenticator.doAuthenticate(new Context("notfound", "wrong", request))).isFalse();
  }
  @Test
  public void testSaslMultipleLdap() {
    LdapSettingsManager settingsManager = new LdapSettingsManager(LdapSettingsFactory.generateAuthenticationSettings(exampleServer, infosupportServer));
    LdapAuthenticator authenticator = new LdapAuthenticator(settingsManager.getContextFactories(), settingsManager.getUserMappings());
    
    assertThat(authenticator.doAuthenticate(new Context("godin", "secret1", request))).isTrue();
    assertThat(authenticator.doAuthenticate(new Context("godin", "wrong", request))).isFalse();
    
    assertThat(authenticator.doAuthenticate(new Context("tester", "secret2", request))).isTrue();
    assertThat(authenticator.doAuthenticate(new Context("tester", "wrong", request))).isFalse();
    
    assertThat(authenticator.doAuthenticate(new Context("notfound", "wrong", request))).isFalse();
    
    assertThat(authenticator.doAuthenticate(new Context("robby", "secret1", request))).isTrue();
    assertThat(authenticator.doAuthenticate(new Context("robby", "wrong", request))).isFalse();
  }
  
  @Test
  public void testPreAuth() {
    Settings settings = LdapSettingsFactory.generateAuthenticationSettings(exampleServer, null);
    settings.setProperty("ldap.preauthentication", "true");
    Mockito.when(request.getHeader(LdapContextFactory.DEFAULT_PRE_AUTH_HEADER_NAME)).thenReturn("godin", "godin", "tester", "tester", "notfound");
    LdapSettingsManager settingsManager = new LdapSettingsManager(settings);
    LdapAuthenticator authenticator = new LdapAuthenticator(settingsManager.getContextFactories(), settingsManager.getUserMappings());
    
    assertThat(authenticator.doAuthenticate(new Context("godin", "secret1", request))).isTrue();
    assertThat(authenticator.doAuthenticate(new Context("godin", "wrong", request))).isTrue();
    
    assertThat(authenticator.doAuthenticate(new Context("tester", "secret2", request))).isTrue();
    assertThat(authenticator.doAuthenticate(new Context("tester", "wrong", request))).isTrue();
    
    assertThat(authenticator.doAuthenticate(new Context("notfound", "wrong", request))).isTrue();
  }

  @Test
  public void testPreAuthMultipleLdap() {
    Settings settings = LdapSettingsFactory.generateAuthenticationSettings(exampleServer, infosupportServer);
    settings.setProperty("ldap.example.preauthentication", "true")
            .setProperty("ldap.infosupport.preauthentication", "true");
    Mockito.when(request.getHeader(LdapContextFactory.DEFAULT_PRE_AUTH_HEADER_NAME))
    .thenReturn("godin", "godin", "tester", "tester", "notfound", "robby", "robby");
    LdapSettingsManager settingsManager = new LdapSettingsManager(settings);
    LdapAuthenticator authenticator = new LdapAuthenticator(settingsManager.getContextFactories(), settingsManager.getUserMappings());

    assertThat(authenticator.doAuthenticate(new Context("godin", "secret1", request))).isTrue();
    assertThat(authenticator.doAuthenticate(new Context("godin", "wrong", request))).isTrue();

    assertThat(authenticator.doAuthenticate(new Context("tester", "secret2", request))).isTrue();
    assertThat(authenticator.doAuthenticate(new Context("tester", "wrong", request))).isTrue();

    assertThat(authenticator.doAuthenticate(new Context("notfound", "wrong", request))).isTrue();

    assertThat(authenticator.doAuthenticate(new Context("robby", "secret1", request))).isTrue();
    assertThat(authenticator.doAuthenticate(new Context("robby", "wrong", request))).isTrue();
  }

}
