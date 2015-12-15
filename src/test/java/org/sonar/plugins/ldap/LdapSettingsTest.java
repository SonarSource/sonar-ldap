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

import org.junit.Test;
import org.sonar.api.config.Settings;

import static org.assertj.core.api.Assertions.assertThat;

public class LdapSettingsTest {
  private static String TEST_LDAP_AUTHENTICATION_METHOD = "SomeAuthMethod";
  private static String TEST_LDAP_CONTEXT_FACTORY = "SomeContextFactory";
  private static String TEST_LDAP_URL = "Ldap url";
  private static String TEST_SERVER_BIND_DN = "server bind dn";
  private static String TEST_SERVER_BIND_PASSWORD = "server bind password";

  private static String TEST_USER_BASE_DN = "User Base Dn";
  private static String TEST_USER_REQUEST = "User Request";
  private static String TEST_USER_EMAIL_ATTRIBUTE = "EmailID";
  private static String TEST_USER_REAL_NAME_ATTR = "Real Name Attr";
  private static String TEST_USER_LOGIN_ATTR = "Login Attr";
  private static String TEST_USER_OBJECT_CLASS = "Object class";

  private static String TEST_GROUP_BASE_DN = "Group BaseDn";
  private static String TEST_GROUP_ID_ATTR = "Id";
  private static String TEST_GROUP_MEMBER = "Member";
  private static String TEST_GROUP_REQUEST = "Group Request";

  @Test
  public void defaults() {
    Settings settings = new Settings();
    LdapSettings ldapSettings = new LdapSettings(settings);
    validateDefaultSettings(ldapSettings);
  }

  @Test
  public void oneLdapServerCustomSettingsTest() {
    Settings settings = new Settings();
    setTestSettingsForOneLdapServer(settings, LdapSettings.LDAP_PROPERTY_PREFIX, "");
    LdapSettings ldapSettings = new LdapSettings(settings);

    assertThat(ldapSettings.getLdapServerKeys()).isEmpty();
    validateCustomSettings(ldapSettings, LdapSettings.LDAP_PROPERTY_PREFIX, "");
  }

  @Test
  public void MultiLdapServerCustomSettingsTest() {
    Settings settings = new Settings().setProperty(LdapSettings.LDAP_SERVERS_PROPERTY, "server1,server2");
    setTestSettingsForOneLdapServer(settings, "server1", "server1");
    setTestSettingsForOneLdapServer(settings, "server2", "server2");
    LdapSettings ldapSettings = new LdapSettings(settings);

    assertThat(ldapSettings.getLdapServerKeys()).isEqualTo(new String[] {"server1", "server2"});
    validateCustomSettings(ldapSettings, "server1", "server1");
    validateCustomSettings(ldapSettings, "server2", "server2");
  }

  @Test
  public void isAutoDiscoveryEnabledTest() {
    Settings settings = new Settings()
      .setProperty(LdapSettings.LDAP_PROPERTY_PREFIX + LdapSettings.LDAP_REALM_PROPERTY_SUFFIX, "realmA");
    LdapSettings ldapSettingsWithAutDiscoveryEnabled = new LdapSettings(settings);
    assertThat(ldapSettingsWithAutDiscoveryEnabled.isAutoDiscoveryEnabled()).isTrue();

    settings = new Settings()
      .setProperty(LdapSettings.LDAP_PROPERTY_PREFIX + LdapSettings.LDAP_REALM_PROPERTY_SUFFIX, "realmA")
      .setProperty(LdapSettings.LDAP_PROPERTY_PREFIX + LdapSettings.LDAP_URL_PROPERTY_SUFFIX, "ldap.server.url");
    LdapSettings ldapSettingsWithAutDiscoveryDisabled = new LdapSettings(settings);
    assertThat(ldapSettingsWithAutDiscoveryDisabled.isAutoDiscoveryEnabled()).isFalse();

    ldapSettingsWithAutDiscoveryDisabled = new LdapSettings(new Settings());
    assertThat(ldapSettingsWithAutDiscoveryDisabled.isAutoDiscoveryEnabled()).isFalse();
  }

  @Test
  public void hasKeyTest() {
    Settings settings = new Settings()
      .setProperty(LdapSettings.LDAP_PROPERTY_PREFIX + LdapSettings.LDAP_REALM_PROPERTY_SUFFIX, "realmA");
    LdapSettings ldapSetting = new LdapSettings(settings);
    assertThat(ldapSetting.hasKey(LdapSettings.LDAP_PROPERTY_PREFIX + LdapSettings.LDAP_REALM_PROPERTY_SUFFIX)).isTrue();
    assertThat(ldapSetting.hasKey(LdapSettings.LDAP_PROPERTY_PREFIX + LdapSettings.LDAP_SERVERS_PROPERTY)).isFalse();
  }

  private void setTestSettingsForOneLdapServer(Settings settings, String settingsKeyPrefix, String settingsValuePrefix) {
    settings.setProperty(settingsKeyPrefix + LdapSettings.AUTHENTICATION_METHOD_PROPERTY_SUFFIX, settingsValuePrefix + TEST_LDAP_AUTHENTICATION_METHOD);
    settings.setProperty(settingsKeyPrefix + LdapSettings.CONTEXT_FACTORY_CLASS_PROPERTY_SUFFIX, settingsValuePrefix + TEST_LDAP_CONTEXT_FACTORY);
    settings.setProperty(settingsKeyPrefix + LdapSettings.LDAP_URL_PROPERTY_SUFFIX, settingsValuePrefix + TEST_LDAP_URL);
    settings.setProperty(settingsKeyPrefix + LdapSettings.LDAP_BIND_DN_PROPERTY_SUFFIX, settingsValuePrefix + TEST_SERVER_BIND_DN);
    settings.setProperty(settingsKeyPrefix + LdapSettings.LDAP_BIND_PWD_PROPERTY_SUFFIX, settingsValuePrefix + TEST_SERVER_BIND_PASSWORD);

    settings.setProperty(settingsKeyPrefix + LdapSettings.User.BASE_DN_PROPERTY_SUFFIX, settingsValuePrefix + TEST_USER_BASE_DN);
    settings.setProperty(settingsKeyPrefix + LdapSettings.User.REQUEST_PROPERTY_SUFFIX, settingsValuePrefix + TEST_USER_REQUEST);
    settings.setProperty(settingsKeyPrefix + LdapSettings.User.EMAIL_ATTRIBUTE_PROPERTY_SUFFIX, settingsValuePrefix + TEST_USER_EMAIL_ATTRIBUTE);
    settings.setProperty(settingsKeyPrefix + LdapSettings.User.REAL_NAME_ATTRIBUTE_PROPERTY_SUFFIX, settingsValuePrefix + TEST_USER_REAL_NAME_ATTR);
    settings.setProperty(settingsKeyPrefix + LdapSettings.User.LOGIN_ATTRIBUTE_PROPERTY_SUFFIX, settingsValuePrefix + TEST_USER_LOGIN_ATTR);
    settings.setProperty(settingsKeyPrefix + LdapSettings.User.OBJECT_CLASS_PROPERTY_SUFFIX, settingsValuePrefix + TEST_USER_OBJECT_CLASS);

    settings.setProperty(settingsKeyPrefix + LdapSettings.Group.BASE_DN_PROPERTY_SUFFIX, settingsValuePrefix + TEST_GROUP_BASE_DN);
    settings.setProperty(settingsKeyPrefix + LdapSettings.Group.ID_ATTRIBUTE_PROPERTY_SUFFIX, settingsValuePrefix + TEST_GROUP_ID_ATTR);
    settings.setProperty(settingsKeyPrefix + LdapSettings.Group.MEMBER_ATTRIBUTE_PROPERTY_SUFFIX, settingsValuePrefix + TEST_GROUP_MEMBER);
    settings.setProperty(settingsKeyPrefix + LdapSettings.Group.REQUEST_PROPERTY_SUFFIX, settingsValuePrefix + TEST_GROUP_REQUEST);
  }

  private void validateCustomSettings(LdapSettings ldapSettings, String settingsPrefix, String testValuePrefix) {
    assertThat(ldapSettings.getLdapAuthenticationOrDefault(settingsPrefix))
      .isEqualTo(testValuePrefix + TEST_LDAP_AUTHENTICATION_METHOD);
    assertThat(ldapSettings.getLdapContextFactoryOrDefault(settingsPrefix))
      .isEqualTo(testValuePrefix + TEST_LDAP_CONTEXT_FACTORY);
    assertThat(ldapSettings.getLdapUrl(settingsPrefix)).isEqualTo(testValuePrefix + TEST_LDAP_URL);
    assertThat(ldapSettings.getBindUserNameDn(settingsPrefix)).isEqualTo(testValuePrefix + TEST_SERVER_BIND_DN);
    assertThat(ldapSettings.getBindPassword(settingsPrefix)).isEqualTo(testValuePrefix + TEST_SERVER_BIND_PASSWORD);

    assertThat(ldapSettings.getUserBaseDn(settingsPrefix)).isEqualTo(testValuePrefix + TEST_USER_BASE_DN);
    assertThat(ldapSettings.getUserRequestOrDefault(settingsPrefix)).isEqualTo(testValuePrefix + TEST_USER_REQUEST);
    assertThat(ldapSettings.getUserEmailAttributeOrDefault(settingsPrefix)).isEqualTo(testValuePrefix + TEST_USER_EMAIL_ATTRIBUTE);
    assertThat(ldapSettings.getUserRealNameAttributeOrDefault(settingsPrefix)).isEqualTo(testValuePrefix + TEST_USER_REAL_NAME_ATTR);
    assertThat(ldapSettings.getUserLoginAttributeOrDefault(settingsPrefix)).isEqualTo(testValuePrefix + TEST_USER_LOGIN_ATTR);
    assertThat(ldapSettings.getUserObjectClassAttributeOrDefault(settingsPrefix)).isEqualTo(testValuePrefix + TEST_USER_OBJECT_CLASS);

    assertThat(ldapSettings.getUserGroupBaseDn(settingsPrefix)).isEqualTo(testValuePrefix + TEST_GROUP_BASE_DN);
    assertThat(ldapSettings.getUserGroupIdAttributeOrDefault(settingsPrefix)).isEqualTo(testValuePrefix + TEST_GROUP_ID_ATTR);
    assertThat(ldapSettings.getUserGroupMemberAttributeOrDefault(settingsPrefix)).isEqualTo(testValuePrefix + TEST_GROUP_MEMBER);
    assertThat(ldapSettings.getUserGroupRequestOrDefault(settingsPrefix)).isEqualTo(testValuePrefix + TEST_GROUP_REQUEST);
  }

  private void validateDefaultSettings(LdapSettings ldapSettings) {
    assertThat(ldapSettings.getLdapContextFactoryOrDefault(LdapSettings.LDAP_PROPERTY_PREFIX))
      .isEqualTo(LdapSettings.DEFAULT_LDAP_CONTEXT_FACTORY);
    assertThat(ldapSettings.getLdapAuthenticationOrDefault(LdapSettings.LDAP_PROPERTY_PREFIX))
      .isEqualTo(LdapSettings.DEFAULT_AUTHENTICATION);

    assertThat(ldapSettings.getLdapServerKeys()).isEmpty();
    assertThat(ldapSettings.getLdapRealm(LdapSettings.LDAP_PROPERTY_PREFIX)).isNull();
    assertThat(ldapSettings.getLdapUrl(LdapSettings.LDAP_PROPERTY_PREFIX)).isNull();
    assertThat(ldapSettings.getLdapUrlKey(LdapSettings.LDAP_PROPERTY_PREFIX)).isEqualTo("ldap.url");
    assertThat(ldapSettings.getBindUserNameDn(LdapSettings.LDAP_PROPERTY_PREFIX)).isNull();
    assertThat(ldapSettings.getBindPassword(LdapSettings.LDAP_PROPERTY_PREFIX)).isNull();

    assertThat(ldapSettings.getUserBaseDn(LdapSettings.LDAP_PROPERTY_PREFIX)).isNull();
    assertThat(ldapSettings.getUserRequestOrDefault(LdapSettings.LDAP_PROPERTY_PREFIX))
      .isEqualTo(LdapSettings.User.DEFAULT_REQUEST);
    assertThat(ldapSettings.getUserEmailAttributeOrDefault(LdapSettings.LDAP_PROPERTY_PREFIX))
      .isEqualTo(LdapSettings.User.DEFAULT_EMAIL_ATTRIBUTE);
    assertThat(ldapSettings.getUserRealNameAttributeOrDefault(LdapSettings.LDAP_PROPERTY_PREFIX))
      .isEqualTo(LdapSettings.User.DEFAULT_REAL_NAME_ATTRIBUTE);
    assertThat(ldapSettings.getUserLoginAttributeOrDefault(LdapSettings.LDAP_PROPERTY_PREFIX))
      .isEqualTo(LdapSettings.User.DEFAULT_LOGIN_ATTRIBUTE);
    assertThat(ldapSettings.getUserLoginAttribute(LdapSettings.LDAP_PROPERTY_PREFIX)).isNull();
    assertThat(ldapSettings.getUserObjectClassAttributeOrDefault(LdapSettings.LDAP_PROPERTY_PREFIX))
      .isEqualTo(LdapSettings.User.DEFAULT_OBJECT_CLASS);
    assertThat(ldapSettings.getUserObjectClassAttribute(LdapSettings.LDAP_PROPERTY_PREFIX)).isNull();

    assertThat(ldapSettings.getUserGroupBaseDn(LdapSettings.LDAP_PROPERTY_PREFIX)).isNull();
    assertThat(ldapSettings.getUserGroupRequestOrDefault(LdapSettings.LDAP_PROPERTY_PREFIX))
      .isEqualTo(LdapSettings.Group.DEFAULT_REQUEST);
    assertThat(ldapSettings.getUserGroupIdAttributeOrDefault(LdapSettings.LDAP_PROPERTY_PREFIX))
      .isEqualTo(LdapSettings.Group.DEFAULT_ID_ATTRIBUTE);
    assertThat(ldapSettings.getUserGroupMemberAttributeOrDefault(LdapSettings.LDAP_PROPERTY_PREFIX))
      .isEqualTo(LdapSettings.Group.DEFAULT_MEMBER_ATTRIBUTE);
    assertThat(ldapSettings.getUserGroupMemberAttribute(LdapSettings.LDAP_PROPERTY_PREFIX)).isNull();
    assertThat(ldapSettings.getUserGroupObjectClassOrDefault(LdapSettings.LDAP_PROPERTY_PREFIX))
      .isEqualTo(LdapSettings.Group.DEFAULT_OBJECT_CLASS);
    assertThat(ldapSettings.getUserGroupObjectClass(LdapSettings.LDAP_PROPERTY_PREFIX)).isNull();
  }
}
