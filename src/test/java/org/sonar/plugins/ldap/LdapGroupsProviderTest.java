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

import java.util.Collection;

import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

public class LdapGroupsProviderTest {

  @ClassRule
  public static LdapServer server = new LdapServer("/static-groups.ldif");

  @Test
  public void test() throws Exception {
    LdapContextFactory contextFactory = LdapContextFactories.createForAnonymousAccess(server.getUrl());
    Settings settings = new Settings()
        .setProperty("ldap.group.baseDn", "ou=groups,dc=example,dc=org")
        .setProperty("ldap.group.memberFormat", "uid=$username,ou=users,dc=example,dc=org");
    LdapGroupMapping groupMapping = new LdapGroupMapping(settings);
    LdapGroupsProvider groupsProvider = new LdapGroupsProvider(contextFactory, groupMapping);

    Collection<String> groups;

    groups = groupsProvider.doGetGroups("tester");
    assertThat(groups.size(), is(1));
    assertThat(groups, hasItem("sonar-users"));

    groups = groupsProvider.doGetGroups("godin");
    assertThat(groups.size(), is(2));
    assertThat(groups, hasItem("sonar-users"));
    assertThat(groups, hasItem("sonar-developers"));

    groupsProvider.doGetGroups("notfound");
  }
}
