/*
 * SonarQube LDAP Plugin
 * Copyright (C) 2009 SonarSource
 * sonarqube@googlegroups.com
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

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.sonar.api.config.Settings;
import org.sonar.api.utils.SonarException;
import org.sonar.plugins.ldap.LdapAutoDiscovery.LdapSrvRecord;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class LdapSettingsManagerTest {

  @Rule
  public ExpectedException thrown = ExpectedException.none();

  @Test
  public void shouldFailWhenNoLdapUrl() throws Exception {
    Settings settings = generateMultipleLdapSettingsWithUserAndGroupMapping();
    settings.removeProperty("ldap.example.url");
    LdapSettingsManager settingsManager = new LdapSettingsManager(settings, new LdapAutoDiscovery());

    thrown.expect(SonarException.class);
    thrown.expectMessage("The property 'ldap.example.url' property is empty while it is mandatory.");
    settingsManager.getContextFactories();
  }

  @Test
  public void shouldFailWhenMixingSingleAndMultipleConfiguration() throws Exception {
    Settings settings = generateMultipleLdapSettingsWithUserAndGroupMapping();
    settings.setProperty("ldap.url", "ldap://foo");
    LdapSettingsManager settingsManager = new LdapSettingsManager(settings, new LdapAutoDiscovery());

    thrown.expect(SonarException.class);
    thrown
      .expectMessage("When defining multiple LDAP servers with the property 'ldap.servers', all " +
        "LDAP properties must be linked to one of those servers. " +
        "Please remove properties like 'ldap.url', 'ldap.realm', ...");
    settingsManager.getContextFactories();
  }

  @Test
  public void testContextFactoriesWithSingleLdap() throws Exception {
    LdapSettingsManager settingsManager = new LdapSettingsManager(
      generateSingleLdapSettingsWithUserAndGroupMapping(), new LdapAutoDiscovery());
    Map<String, LdapContextFactory> contextFactories = settingsManager.getContextFactories();
    assertThat(contextFactories.keySet()).isEqualTo(getSingleLdapServerKeySet());
  }

  @Test
  public void testContextFactoriesWithAutoDiscovery() throws Exception {
    int ldapServerCount = 2;
    LdapAutoDiscovery ldapAutoDiscovery = getTestLdapAutoDiscoveryObject(ldapServerCount);
    LinkedHashSet<String> keyList = getAutoDiscoveredLdapServersKeySet(ldapServerCount);
    LdapSettingsManager settingsManager = new LdapSettingsManager(generateAutoDiscoverySettings(), ldapAutoDiscovery);

    Map<String, LdapContextFactory> contextFactoryMap = settingsManager.getContextFactories();

    assertThat(contextFactoryMap.keySet()).isEqualTo(keyList);
  }

  @Test
  public void testContextFactoriesWithAutoDiscoveryFailed() throws Exception {
    LdapAutoDiscovery ldapAutoDiscovery = mock(LdapAutoDiscovery.class);
    when(ldapAutoDiscovery.getLdapServers("example.org")).thenReturn(Collections.<LdapSrvRecord>emptyList());
    LdapSettingsManager settingsManager = new LdapSettingsManager(generateAutoDiscoverySettings(), ldapAutoDiscovery);

    thrown.expect(SonarException.class);
    thrown.expectMessage("The property 'ldap.url' is empty and SonarQube is not able to auto-discover any LDAP server.");

    settingsManager.getContextFactories();
  }

  /**
   * Test there are 2 @link{org.sonar.plugins.ldap.LdapContextFactory}s found.
   *
   * @throws Exception
   *             This is not expected.
   */
  @Test
  public void testContextFactoriesWithMultipleLdap() throws Exception {
    LdapSettingsManager settingsManager = new LdapSettingsManager(
      generateMultipleLdapSettingsWithUserAndGroupMapping(), new LdapAutoDiscovery());
    assertThat(settingsManager.getContextFactories().size()).isEqualTo(2);
    // We do it twice to make sure the settings keep the same.
    assertThat(settingsManager.getContextFactories().size()).isEqualTo(2);
  }

  @Test
  public void testUserMappingsWithSingleLdap() throws Exception {
    LdapSettingsManager settingsManager = new LdapSettingsManager(
      generateSingleLdapSettingsWithUserAndGroupMapping(), new LdapAutoDiscovery());
    Map<String, LdapUserMapping> userMappings = settingsManager.getUserMappings();
    assertThat(userMappings.keySet()).isEqualTo(getSingleLdapServerKeySet());
  }

  @Test
  public void testUserMappingsWithAutoDiscovery() throws Exception {
    int ldapServerCount = 2;
    LdapAutoDiscovery ldapAutoDiscovery = getTestLdapAutoDiscoveryObject(ldapServerCount);
    LinkedHashSet<String> keyList = getAutoDiscoveredLdapServersKeySet(ldapServerCount);
    LdapSettingsManager settingsManager = new LdapSettingsManager(generateAutoDiscoverySettings(), ldapAutoDiscovery);

    Map<String, LdapUserMapping> userMappings = settingsManager.getUserMappings();

    assertThat(userMappings.keySet()).isEqualTo(keyList);
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
      generateMultipleLdapSettingsWithUserAndGroupMapping(), new LdapAutoDiscovery());
    assertThat(settingsManager.getGroupMappings().size()).isEqualTo(2);
    // We do it twice to make sure the settings keep the same.
    assertThat(settingsManager.getGroupMappings().size()).isEqualTo(2);
  }

  @Test
  public void testGroupMappingsWithSingleLdap() throws Exception {
    LdapSettingsManager settingsManager = new LdapSettingsManager(
      generateSingleLdapSettingsWithUserAndGroupMapping(), new LdapAutoDiscovery());
    Map<String, LdapGroupMapping> groupMappings = settingsManager.getGroupMappings();

    assertThat(groupMappings.keySet()).isEqualTo(getSingleLdapServerKeySet());
  }

  @Test
  public void testGroupMappingsWithAutoDiscovery() throws Exception {
    int ldapServerCount = 2;
    LdapAutoDiscovery ldapAutoDiscovery = getTestLdapAutoDiscoveryObject(ldapServerCount);
    LinkedHashSet<String> keyList = getAutoDiscoveredLdapServersKeySet(2);
    LdapSettingsManager settingsManager = new LdapSettingsManager(generateAutoDiscoverySettings(), ldapAutoDiscovery);

    Map<String, LdapGroupMapping> groupMappings = settingsManager.getGroupMappings();
    assertThat(groupMappings.keySet()).isEqualTo(keyList);
  }

  /**
   * Test there are 2 @link{org.sonar.plugins.ldap.LdapUserMapping}s found.
   *
   * @throws Exception
   *             This is not expected.
   */
  @Test
  public void testUserMappingsWithMultipleLdap() throws Exception {
    LdapSettingsManager settingsManager = new LdapSettingsManager(
      generateMultipleLdapSettingsWithUserAndGroupMapping(), new LdapAutoDiscovery());
    assertThat(settingsManager.getUserMappings().size()).isEqualTo(2);
    // We do it twice to make sure the settings keep the same.
    assertThat(settingsManager.getUserMappings().size()).isEqualTo(2);
  }

  /**
   * Test what happens when no configuration is set.
   * Normally there will be a contextFactory, but the auto-discovery doesn't work for the test server.
   * @throws Exception
   */
  @Test
  public void testEmptySettings() throws Exception {
    LdapSettingsManager settingsManager = new LdapSettingsManager(
      new Settings(), new LdapAutoDiscovery());

    thrown.expect(SonarException.class);
    thrown.expectMessage("The property 'ldap.url' is empty and no realm configured to try auto-discovery.");
    settingsManager.getContextFactories();
  }

  private Settings generateMultipleLdapSettingsWithUserAndGroupMapping() {
    Settings settings = new Settings();

    settings.setProperty("ldap.servers", "example,infosupport");

    settings.setProperty("ldap.example.url", "/users.example.org.ldif")
      .setProperty("ldap.example.user.baseDn", "ou=users,dc=example,dc=org")
      .setProperty("ldap.example.group.baseDn", "ou=groups,dc=example,dc=org")
      .setProperty("ldap.example.group.request", "(&(objectClass=posixGroup)(memberUid={uid}))");

    settings.setProperty("ldap.infosupport.url", "/users.infosupport.com.ldif")
      .setProperty("ldap.infosupport.user.baseDn", "ou=users,dc=infosupport,dc=com")
      .setProperty("ldap.infosupport.group.baseDn", "ou=groups,dc=infosupport,dc=com")
      .setProperty("ldap.infosupport.group.request", "(&(objectClass=posixGroup)(memberUid={uid}))");

    return settings;
  }

  private Settings generateSingleLdapSettingsWithUserAndGroupMapping() {
    Settings settings = new Settings();

    settings.setProperty("ldap.url", "/users.example.org.ldif")
      .setProperty("ldap.user.baseDn", "ou=users,dc=example,dc=org")
      .setProperty("ldap.group.baseDn", "ou=groups,dc=example,dc=org")
      .setProperty("ldap.group.request", "(&(objectClass=posixGroup)(memberUid={uid}))");

    return settings;
  }

  private Settings generateAutoDiscoverySettings() {
    Settings settings = new Settings();

    settings.setProperty("ldap.realm", "example.org")
      .setProperty("ldap.user.baseDn", "ou=users,dc=example,dc=org")
      .setProperty("ldap.group.baseDn", "ou=groups,dc=example,dc=org")
      .setProperty("ldap.group.request", "(&(objectClass=posixGroup)(memberUid={uid}))");

    return settings;
  }

  private static LdapAutoDiscovery getTestLdapAutoDiscoveryObject(int serverCount) {
    List<LdapSrvRecord> ldapSrvRecords = new ArrayList<>();
    for (int i = 0; i < serverCount; i++) {
      ldapSrvRecords.add(new LdapSrvRecord("ldap://localhost:189" + i, 1, 1));
    }

    LdapAutoDiscovery ldapAutoDiscovery = mock(LdapAutoDiscovery.class);
    when(ldapAutoDiscovery.getLdapServers("example.org")).thenReturn(ldapSrvRecords);

    return ldapAutoDiscovery;
  }

  private static LinkedHashSet<String> getSingleLdapServerKeySet() {
    LinkedHashSet<String> keyList = new LinkedHashSet<>();
    keyList.add(LdapSettingsManager.DEFAULT_LDAP_SERVER_KEY);

    return keyList;
  }

  private static LinkedHashSet<String> getAutoDiscoveredLdapServersKeySet(int serverCount) {
    LinkedHashSet<String> keyList = new LinkedHashSet<>();
    for (int i = 1; i <= serverCount; i++) {
      keyList.add(LdapSettingsManager.DEFAULT_LDAP_SERVER_KEY + i);
    }

    return keyList;
  }

}
