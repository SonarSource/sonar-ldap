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

import static org.fest.assertions.Assertions.assertThat;

public class LdapGroupsProviderTest {

  @ClassRule
  public static LdapServer server = new LdapServer("/static-groups.ldif");

  @Test
  public void defaults() throws Exception {
    LdapContextFactory contextFactory = LdapContextFactories.createForAnonymousAccess(server.getUrl());
    Settings settings = new Settings()
        .setProperty("ldap.user.baseDn", "ou=users,dc=example,dc=org")
        .setProperty("ldap.group.baseDn", "ou=groups,dc=example,dc=org");
    LdapUserMapping userMapping = new LdapUserMapping(settings);
    LdapGroupMapping groupMapping = new LdapGroupMapping(settings);
    LdapGroupsProvider groupsProvider = new LdapGroupsProvider(contextFactory, userMapping, groupMapping);

    Collection<String> groups;

    groups = groupsProvider.doGetGroups("tester");
    assertThat(groups).containsOnly("sonar-users");

    groups = groupsProvider.doGetGroups("godin");
    assertThat(groups).containsOnly("sonar-users", "sonar-developers");

    groups = groupsProvider.doGetGroups("notfound");
    assertThat(groups).isEmpty();
  }

  @Test
  public void posix() {
    LdapContextFactory contextFactory = LdapContextFactories.createForAnonymousAccess(server.getUrl());
    Settings settings = new Settings()
        .setProperty("ldap.user.baseDn", "ou=users,dc=example,dc=org")
        .setProperty("ldap.group.baseDn", "ou=groups,dc=example,dc=org")
        .setProperty("ldap.group.request", "(&(objectClass=posixGroup)(memberUid={uid}))");
    LdapUserMapping userMapping = new LdapUserMapping(settings);
    LdapGroupMapping groupMapping = new LdapGroupMapping(settings);
    LdapGroupsProvider groupsProvider = new LdapGroupsProvider(contextFactory, userMapping, groupMapping);

    Collection<String> groups;

    groups = groupsProvider.doGetGroups("godin");
    assertThat(groups).containsOnly("linux-users");
  }

  @Test
  public void mixed() {
    LdapContextFactory contextFactory = LdapContextFactories.createForAnonymousAccess(server.getUrl());
    Settings settings = new Settings()
        .setProperty("ldap.user.baseDn", "ou=users,dc=example,dc=org")
        .setProperty("ldap.group.baseDn", "ou=groups,dc=example,dc=org")
        .setProperty("ldap.group.request", "(&(|(objectClass=groupOfUniqueNames)(objectClass=posixGroup))(|(uniqueMember={dn})(memberUid={uid})))");
    LdapUserMapping userMapping = new LdapUserMapping(settings);
    LdapGroupMapping groupMapping = new LdapGroupMapping(settings);
    LdapGroupsProvider groupsProvider = new LdapGroupsProvider(contextFactory, userMapping, groupMapping);

    Collection<String> groups;

    groups = groupsProvider.doGetGroups("godin");
    assertThat(groups).containsOnly("sonar-users", "sonar-developers", "linux-users");
  }

}
