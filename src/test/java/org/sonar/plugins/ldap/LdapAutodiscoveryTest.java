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

import org.junit.Test;

import java.net.UnknownHostException;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertThat;

public class LdapAutodiscoveryTest {

  @Test
  public void testGetDnsDomain() throws UnknownHostException {
    assertThat(LdapAutodiscovery.getDnsDomainName("localhost"), nullValue());
    assertThat(LdapAutodiscovery.getDnsDomainName("godin.example.org"), is("example.org"));
    assertThat(LdapAutodiscovery.getDnsDomainName("godin.usr.example.org"), is("usr.example.org"));
  }

  @Test
  public void testGetDnsDomainDn() {
    assertThat(LdapAutodiscovery.getDnsDomainDn("example.org"), is("dc=example,dc=org"));
  }

}
