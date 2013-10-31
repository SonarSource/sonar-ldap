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
import org.mockito.Mockito;
import org.sonar.api.config.Settings;
import org.sonar.api.security.ExternalGroupsProvider;
import org.sonar.api.security.ExternalUsersProvider;
import org.sonar.api.utils.SonarException;
import org.sonar.plugins.ldap.server.LdapServer;

import javax.servlet.http.HttpServletRequest;

import static org.fest.assertions.Assertions.assertThat;
import static org.junit.Assert.fail;

public class LdapRealmTest {

  @ClassRule
  public static LdapServer server = new LdapServer("/users.example.org.ldif");

  @Test
  public void normal() {
    Settings settings = new Settings()
        .setProperty("ldap.url", server.getUrl());
    LdapRealm realm = new LdapRealm(settings);
    assertThat(realm.getName()).isEqualTo("LDAP");
    realm.init();
    assertThat(realm.getUsersProvider()).isInstanceOf(ExternalUsersProvider.class).isInstanceOf(LdapUsersProvider.class);
    assertThat(realm.getGroupsProvider()).isNull();
  }

  @Test
  public void noConnection() {
    Settings settings = new Settings()
        .setProperty("ldap.url", "ldap://no-such-host")
        .setProperty("ldap.group.baseDn", "cn=groups,dc=example,dc=org");
    LdapRealm realm = new LdapRealm(settings);
    assertThat(realm.getName()).isEqualTo("LDAP");
    try {
      realm.init();
      fail("Since there is no connection, the init method has to throw an exception.");
    } catch (SonarException e) {
      assertThat(e.getMessage()).contains("Unable to open LDAP connection");
    }
    assertThat(realm.getUsersProvider()).isInstanceOf(ExternalUsersProvider.class).isInstanceOf(LdapUsersProvider.class);
    assertThat(realm.getGroupsProvider()).isInstanceOf(ExternalGroupsProvider.class).isInstanceOf(LdapGroupsProvider.class);
    ExternalUsersProvider.Context context = new ExternalUsersProvider.Context("tester", Mockito.mock(HttpServletRequest.class));
    try {
      realm.getUsersProvider().doGetUserDetails(context);
      fail("Since there is no connection, the doGetUserDetails method has to throw an exception.");
    } catch (SonarException e) {
      assertThat(e.getMessage()).contains("Unable to retrieve user details: No user mappings found.");
    }
    try {
      realm.getGroupsProvider().doGetGroups("tester");
      fail("Since there is no connection, the doGetGroups method has to throw an exception.");
    } catch (SonarException e) {
      assertThat(e.getMessage()).contains("Unable to retrieve details for user tester");
    }
  }

}
