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

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.sonar.api.config.Settings;
import org.sonar.api.utils.SonarException;

import static org.fest.assertions.Assertions.assertThat;

public class LdapSettingsManagerTest {

  @Rule
  public ExpectedException thrown = ExpectedException.none();

  @Test
  public void shouldFailWhenNoLdapUrl() throws Exception {
    Settings settings = generateMultipleLdapSettingsWithUserAndGroupMapping();
    settings.removeProperty("ldap.example.url");
    LdapSettingsManager settingsManager = new LdapSettingsManager(settings);

    thrown.expect(SonarException.class);
    thrown.expectMessage("The property 'ldap.example.url' property is empty and SonarQube is not able to auto-discover any LDAP server.");
    settingsManager.getContextFactories();
  }

  @Test
  public void shouldFailWhenMixingSingleAndMultipleConfiguration() throws Exception {
    Settings settings = generateMultipleLdapSettingsWithUserAndGroupMapping();
    settings.setProperty("ldap.url", "ldap://foo");
    LdapSettingsManager settingsManager = new LdapSettingsManager(settings);

    thrown.expect(SonarException.class);
    thrown
        .expectMessage("When defining multiple LDAP servers with the property 'ldap.servers', all LDAP properties must be linked to one of those servers. Please remove properties like 'ldap.url', 'ldap.realm', ...");
    settingsManager.getContextFactories();
  }

  /**
   * Test there are 2 @link{org.sonar.plugins.ldap.LdapContextFactory}s found.
   *
   * @throws Exception
   *             This is not expected.
   */
  @Test
  public void testContextFactories() throws Exception {
    LdapSettingsManager settingsManager = new LdapSettingsManager(
        generateMultipleLdapSettingsWithUserAndGroupMapping());
    assertThat(settingsManager.getContextFactories().size()).isEqualTo(2);
    // We do it twice to make sure the settings keep the same.
    assertThat(settingsManager.getContextFactories().size()).isEqualTo(2);
  }

  /**
   * Test there are 2 @link{org.sonar.plugins.ldap.LdapUserMapping}s found.
   *
   * @throws Exception
   *             This is not expected.
   */
  @Test
  public void testUserMappings() throws Exception {
    LdapSettingsManager settingsManager = new LdapSettingsManager(
        generateMultipleLdapSettingsWithUserAndGroupMapping());
    assertThat(settingsManager.getUserMappings().size()).isEqualTo(2);
    // We do it twice to make sure the settings keep the same.
    assertThat(settingsManager.getUserMappings().size()).isEqualTo(2);
  }

  /**
   * Test there are 2 @link{org.sonar.plugins.ldap.LdapGroupMapping}s found.
   *
   * @throws Exception
   *             This is not expected.
   */
  @Test
  public void testGroupMappings() throws Exception {
    LdapSettingsManager settingsManager = new LdapSettingsManager(
        generateMultipleLdapSettingsWithUserAndGroupMapping());
    assertThat(settingsManager.getGroupMappings().size()).isEqualTo(2);
    // We do it twice to make sure the settings keep the same.
    assertThat(settingsManager.getGroupMappings().size()).isEqualTo(2);
  }

  /**
   * Test what happens when no configuration is set.
   * Normally there will be a contextFactory, but the autodiscovery doesn't work for the test server.
   * @throws Exception
   */
  @Test
  public void testEmptySettings() throws Exception {
    LdapSettingsManager settingsManager = new LdapSettingsManager(
        new Settings());

    thrown.expect(SonarException.class);
    thrown.expectMessage("The property 'ldap.url' property is empty and SonarQube is not able to auto-discover any LDAP server.");
    settingsManager.getContextFactories();
  }

  private Settings generateMultipleLdapSettingsWithUserAndGroupMapping() {
    Settings settings = new Settings();

    settings.setProperty("ldap.servers", "example,infosupport");

    settings.setProperty("ldap.example.url", "/users.example.org.ldif")
        .setProperty("ldap.example.user.baseDn", "ou=users,dc=example,dc=org")
        .setProperty("ldap.example.group.baseDn", "ou=groups,dc=example,dc=org")
        .setProperty("ldap.example.group.request",
            "(&(objectClass=posixGroup)(memberUid={uid}))");

    settings.setProperty("ldap.infosupport.url", "/users.infosupport.com.ldif")
        .setProperty("ldap.infosupport.user.baseDn",
            "ou=users,dc=infosupport,dc=com")
        .setProperty("ldap.infosupport.group.baseDn",
            "ou=groups,dc=infosupport,dc=com")
        .setProperty("ldap.infosupport.group.request",
            "(&(objectClass=posixGroup)(memberUid={uid}))");

    return settings;
  }
}
