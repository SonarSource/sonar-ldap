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

  @Test
  public void defaults() throws Exception {
    Settings settings = LdapSettingsFactory.generateSimpleAnonymousAccessSettings(exampleServer, null);

    LdapSettingsManager settingsManager = new LdapSettingsManager(settings, new LdapAutodiscovery());
    LdapGroupsProvider groupsProvider = new LdapGroupsProvider(settingsManager.getContextFactories(), settingsManager.getUserMappings(), settingsManager.getGroupMappings());
    Collection<String> groups;

    groups = groupsProvider.doGetGroups("tester");
    assertThat(groups).containsOnly("sonar-users", "example-cross-users");

    groups = groupsProvider.doGetGroups("godin");
    assertThat(groups).containsOnly("sonar-users", "sonar-developers");

    groups = groupsProvider.doGetGroups("notfound");
    assertThat(groups).isEmpty();
  }

  @Test
  public void defaultsMultipleLdap() throws Exception {
    Settings settings = LdapSettingsFactory.generateSimpleAnonymousAccessSettings(exampleServer, infosupportServer);

    LdapSettingsManager settingsManager = new LdapSettingsManager(settings, new LdapAutodiscovery());
    LdapGroupsProvider groupsProvider = new LdapGroupsProvider(settingsManager.getContextFactories(), settingsManager.getUserMappings(), settingsManager.getGroupMappings());

    Collection<String> groups;

    groups = groupsProvider.doGetGroups("tester");
    assertThat(groups).containsOnly("sonar-users", "example-cross-users");

    groups = groupsProvider.doGetGroups("godin");
    assertThat(groups).containsOnly("sonar-users", "sonar-developers");

    groups = groupsProvider.doGetGroups("notfound");
    assertThat(groups).isEmpty();

    groups = groupsProvider.doGetGroups("testerInfo");
    assertThat(groups).containsOnly("sonar-users", "infosupport-cross-users");

    groups = groupsProvider.doGetGroups("robby");
    assertThat(groups).containsOnly("sonar-users", "sonar-developers");
  }

  @Test
  public void posix() {
    Settings settings = LdapSettingsFactory.generateSimpleAnonymousAccessSettings(exampleServer, null);
    settings.setProperty("ldap.group.request", "(&(objectClass=posixGroup)(memberUid={uid}))");
    LdapSettingsManager settingsManager = new LdapSettingsManager(settings, new LdapAutodiscovery());
    LdapGroupsProvider groupsProvider = new LdapGroupsProvider(settingsManager.getContextFactories(), settingsManager.getUserMappings(), settingsManager.getGroupMappings());

    Collection<String> groups;

    groups = groupsProvider.doGetGroups("godin");
    assertThat(groups).containsOnly("linux-users");
  }

  @Test
  public void posixMultipleLdap() {
    Settings settings = LdapSettingsFactory.generateSimpleAnonymousAccessSettings(exampleServer, infosupportServer);
    settings.setProperty("ldap.example.group.request", "(&(objectClass=posixGroup)(memberUid={uid}))");
    settings.setProperty("ldap.infosupport.group.request", "(&(objectClass=posixGroup)(memberUid={uid}))");
    LdapSettingsManager settingsManager = new LdapSettingsManager(settings, new LdapAutodiscovery());
    LdapGroupsProvider groupsProvider = new LdapGroupsProvider(settingsManager.getContextFactories(), settingsManager.getUserMappings(), settingsManager.getGroupMappings());

    Collection<String> groups;

    groups = groupsProvider.doGetGroups("godin");
    assertThat(groups).containsOnly("linux-users");

    groups = groupsProvider.doGetGroups("robby");
    assertThat(groups).containsOnly("linux-users");
  }

  @Test
  public void mixed() {
    Settings settings = LdapSettingsFactory.generateSimpleAnonymousAccessSettings(exampleServer, infosupportServer);
    settings.setProperty("ldap.example.group.request", "(&(|(objectClass=groupOfUniqueNames)(objectClass=posixGroup))(|(uniqueMember={dn})(memberUid={uid})))");
    LdapSettingsManager settingsManager = new LdapSettingsManager(settings, new LdapAutodiscovery());
    LdapGroupsProvider groupsProvider = new LdapGroupsProvider(settingsManager.getContextFactories(), settingsManager.getUserMappings(), settingsManager.getGroupMappings());

    Collection<String> groups;

    groups = groupsProvider.doGetGroups("godin");
    assertThat(groups).containsOnly("sonar-users", "sonar-developers", "linux-users");
  }

  @Test
  public void mixedMultipleLdap() {
    Settings settings = LdapSettingsFactory.generateSimpleAnonymousAccessSettings(exampleServer, infosupportServer);
    settings.setProperty("ldap.example.group.request", "(&(|(objectClass=groupOfUniqueNames)(objectClass=posixGroup))(|(uniqueMember={dn})(memberUid={uid})))");
    settings.setProperty("ldap.infosupport.group.request", "(&(|(objectClass=groupOfUniqueNames)(objectClass=posixGroup))(|(uniqueMember={dn})(memberUid={uid})))");
    LdapSettingsManager settingsManager = new LdapSettingsManager(settings, new LdapAutodiscovery());
    LdapGroupsProvider groupsProvider = new LdapGroupsProvider(settingsManager.getContextFactories(), settingsManager.getUserMappings(), settingsManager.getGroupMappings());

    Collection<String> groups;

    groups = groupsProvider.doGetGroups("godin");
    assertThat(groups).containsOnly("sonar-users", "sonar-developers", "linux-users");

    groups = groupsProvider.doGetGroups("robby");
    assertThat(groups).containsOnly("sonar-users", "sonar-developers", "linux-users");
  }
  
  @Test
  public void multipleLdapWithExternalGroupsDefaultBehavior() {
    Settings settings = LdapSettingsFactory.generateSimpleAnonymousAccessSettings(exampleServer, infosupportServer);
    LdapSettingsManager settingsManager = new LdapSettingsManager(settings, new LdapAutodiscovery());
    LdapGroupsProvider groupsProvider = new LdapGroupsProvider(settingsManager.getContextFactories(), settingsManager.getUserMappings(), settingsManager.getGroupMappings());

    Collection<String> groups;

    groups = groupsProvider.doGetGroups("tester");
    assertThat(groups).containsOnly("sonar-users", "example-cross-users");

    groups = groupsProvider.doGetGroups("testerinfo");
    assertThat(groups).containsOnly("sonar-users", "infosupport-cross-users");
  }
  
  @Test
  public void multipleLdapWithExternalGroupsSpecificServer() {
    Settings settings = LdapSettingsFactory.generateSimpleAnonymousAccessSettings(exampleServer, infosupportServer);
    settings.setProperty("ldap.example.group.searchServers", "infosupport");
    LdapSettingsManager settingsManager = new LdapSettingsManager(settings, new LdapAutodiscovery());
    LdapGroupsProvider groupsProvider = new LdapGroupsProvider(settingsManager.getContextFactories(), settingsManager.getUserMappings(), settingsManager.getGroupMappings());

    Collection<String> groups;

    groups = groupsProvider.doGetGroups("tester");
    assertThat(groups).containsOnly("infosupport-cross-users");

    groups = groupsProvider.doGetGroups("testerinfo");
    assertThat(groups).containsOnly("sonar-users", "infosupport-cross-users");
  }
  
  @Test
  public void multipleLdapWithExternalGroupsSpecificListOfServer() {
    Settings settings = LdapSettingsFactory.generateSimpleAnonymousAccessSettings(exampleServer, infosupportServer);
    settings.setProperty("ldap.example.group.searchServers", "example,infosupport");
    LdapSettingsManager settingsManager = new LdapSettingsManager(settings, new LdapAutodiscovery());
    LdapGroupsProvider groupsProvider = new LdapGroupsProvider(settingsManager.getContextFactories(), settingsManager.getUserMappings(), settingsManager.getGroupMappings());

    Collection<String> groups;

    groups = groupsProvider.doGetGroups("tester");
    assertThat(groups).containsOnly("sonar-users", "infosupport-cross-users", "example-cross-users");

    groups = groupsProvider.doGetGroups("testerinfo");
    assertThat(groups).containsOnly("sonar-users", "infosupport-cross-users");
  }
  
  
}
