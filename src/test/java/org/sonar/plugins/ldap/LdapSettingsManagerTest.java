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

import static org.fest.assertions.Assertions.assertThat;
import org.junit.Test;
import org.sonar.api.config.Settings;

/**
 * Here we test the settingsManagers ability to cope with multiple ldap servers.
 */
public class LdapSettingsManagerTest {

    /**
     * Test there are 2 @link{org.sonar.plugins.ldap.LdapContextFactory}s found.
     * @throws Exception This is not expected.
     */
    @Test
    public void testContextFactories() throws Exception {
        LdapSettingsManager settingsManager = new LdapSettingsManager(generateMultipleLdapSettingsWithUserAndGroupMapping());
        assertThat(settingsManager.getContextFactories().size()).isEqualTo(2);
    }

    /**
     * Test there are 2 @link{org.sonar.plugins.ldap.LdapUserMapping}s found.
     * @throws Exception This is not expected.
     */
    @Test
    public void testUserMappings() throws Exception{
        LdapSettingsManager settingsManager = new LdapSettingsManager(generateMultipleLdapSettingsWithUserAndGroupMapping());
        assertThat(settingsManager.getUserMappings().size()).isEqualTo(2);
    }

    /**
     * Test there are 2 @link{org.sonar.plugins.ldap.LdapGroupMapping}s found.
     * @throws Exception This is not expected.
     */
    @Test
    public void testGroupMappings() throws Exception{
        LdapSettingsManager settingsManager = new LdapSettingsManager(generateMultipleLdapSettingsWithUserAndGroupMapping());
        assertThat(settingsManager.getGroupMappings().size()).isEqualTo(2);
    }

    private Settings generateMultipleLdapSettingsWithUserAndGroupMapping() {
        Settings settings = new Settings();
        settings.setProperty("ldap.url", "/users.example.org.ldif")
                .setProperty("ldap.user.baseDn", "ou=users,dc=example,dc=org")
                .setProperty("ldap.group.baseDn", "ou=groups,dc=example,dc=org")
                .setProperty("ldap.group.request", "(&(objectClass=posixGroup)(memberUid={uid}))");

        settings.setProperty("ldap1.url", "/users.infosupport.com.ldif")
                .setProperty("ldap1.user.baseDn", "ou=users,dc=infosupport,dc=com")
                .setProperty("ldap1.group.baseDn", "ou=groups,dc=infosupport,dc=com")
                .setProperty("ldap1.group.request", "(&(objectClass=posixGroup)(memberUid={uid}))");

        return settings;
    }
}
