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

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.teklabs.throng.integration.ldap.Ldap;
import org.junit.Before;
import org.junit.Test;
import org.sonar.api.utils.SonarException;

import javax.naming.NamingException;

public class LdapAuthenticatorTest {

  private LdapAuthenticator authenticator;

  @Before
  public void setUp() throws Exception {
    Ldap ldap = mock(Ldap.class);
    doThrow(new NamingException()).when(ldap).testConnection();
    doThrow(new NamingException()).when(ldap).authenticate(anyString(), anyString());
    LdapConfiguration configuration = mock(LdapConfiguration.class);
    when(configuration.getLdap()).thenReturn(ldap);
    authenticator = new LdapAuthenticator(configuration);
  }

  @Test(expected = SonarException.class)
  public void shouldFailWhenUnableToTestConnection() throws Exception {
    authenticator.init();
  }

  @Test
  public void shouldNotFailWhenUnableToAuthenticate() throws Exception {
    assertThat(authenticator.authenticate("", ""), is(false));
  }

}
