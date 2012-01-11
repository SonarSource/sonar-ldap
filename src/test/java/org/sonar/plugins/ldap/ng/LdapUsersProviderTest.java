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
package org.sonar.plugins.ldap.ng;

import org.junit.ClassRule;
import org.junit.Test;
import org.sonar.api.security.UserDetails;
import org.sonar.api.utils.SonarException;
import org.sonar.plugins.ldap.server.LdapServer;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

public class LdapUsersProviderTest {

  @ClassRule
  public static LdapServer server = new LdapServer("/users.ldif");

  @Test
  public void test() throws Exception {
    LdapContextFactory contextFactory = new LdapContextFactory(server.getUrl());
    LdapUserMapping userMapping = new LdapUserMapping();
    LdapUsersProvider usersProvider = new LdapUsersProvider(contextFactory, userMapping);

    UserDetails details;

    details = usersProvider.doGetUserDetails("godin");
    assertThat(details.getName(), is("Evgeny Mandrikov"));
    assertThat(details.getEmail(), is("godin@example.org"));

    details = usersProvider.doGetUserDetails("tester");
    assertThat(details.getName(), is("Tester Testerovich"));
    assertThat(details.getEmail(), is("tester@example.org"));

    details = usersProvider.doGetUserDetails("without_email");
    assertThat(details.getName(), is("Without Email"));
    assertThat(details.getEmail(), is(""));

    try {
      usersProvider.doGetUserDetails("notfound");
    } catch (SonarException e) {
      assertThat(e.getMessage(), containsString("Unable to retrieve details for user notfound"));
    }
  }

}
