/*
 * SonarQube LDAP Plugin
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

import org.apache.commons.collections.CollectionUtils;
import org.junit.Test;
import org.mockito.Mockito;
import org.sonar.api.config.Settings;
import org.sonar.plugins.ldap.windows.WindowsAuthenticationHelper;
import org.sonar.plugins.ldap.windows.servlet.WindowsGroupsProviderFilter;
import org.sonar.plugins.ldap.windows.servlet.WindowsLogoutFilter;
import org.sonar.plugins.ldap.windows.WindowsSecurityRealm;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class LdapExtensionsTest {
    @Test
    public void provideTests() {
        Settings settings = new Settings();
        LdapExtensions ldapExtensions = new LdapExtensions(settings);

        Object ldapExtensionsObject = ldapExtensions.provide();
        assertThat(ldapExtensionsObject).isNotNull();
    }

    @Test
    public void getExtensionsDefaultOnWindowsTests() {
        this.runGetExtensionsDefaultTest(true, this.getExpectedWindowsExtensions());
    }

    @Test
    public void getExtensionsDefaultOnNonWindowsOsTests() {
        this.runGetExtensionsDefaultTest(false, this.getExpectedLdapExtensions());
    }

    @Test
    public void getExtensionsForWindowsSecurity() {
        this.runGetExtensionsTest("true", true, this.getExpectedWindowsExtensions());
    }

    @Test
    public void getExtensionsForLdapRealm() {
        this.runGetExtensionsTest("ldap", false, this.getExpectedLdapExtensions());
        this.runGetExtensionsTest("", false, this.getExpectedLdapExtensions());
        this.runGetExtensionsTest(null, false, this.getExpectedLdapExtensions());
        this.runGetExtensionsTest("", true, this.getExpectedLdapExtensions());
        this.runGetExtensionsTest(null, true, this.getExpectedWindowsExtensions());
        this.runGetExtensionsTest("ldap", true, this.getExpectedLdapExtensions());
    }

    @Test(expected = IllegalArgumentException.class)
    public void getExtensionsThrowsException() {
        Settings settings = new Settings();
        settings.setProperty(LdapExtensions.SONAR_LDAP_WINDOWS_AUTH, "true");
        SystemUtilsWrapper systemUtilsWrapper = Mockito.mock(SystemUtilsWrapper.class);
        Mockito.when(systemUtilsWrapper.isOperatingSystemWindows()).thenReturn(false);

        LdapExtensions ldapExtensions = new LdapExtensions(settings, systemUtilsWrapper);

        ldapExtensions.getExtensions();
    }

    private void runGetExtensionsDefaultTest(boolean isOperatingSystemWindows, List<Class> expectedExtensions) {
        Settings settings = new Settings();
        SystemUtilsWrapper systemUtilsWrapper = Mockito.mock(SystemUtilsWrapper.class);
        Mockito.when(systemUtilsWrapper.isOperatingSystemWindows()).thenReturn(isOperatingSystemWindows);
        LdapExtensions ldapExtensions = new LdapExtensions(settings, systemUtilsWrapper);

        List<Class> extensions = ldapExtensions.getExtensions();

        assertThat(extensions).isNotNull();
        assertThat(CollectionUtils.isEqualCollection(extensions, expectedExtensions)).isTrue();
    }

    private void runGetExtensionsTest(String windowsAuthSettingValue, boolean isOperatingSystemWindows, List<Class> expectedExtensions) {
        Settings settings = new Settings();
        settings.setProperty(LdapExtensions.SONAR_LDAP_WINDOWS_AUTH, windowsAuthSettingValue);

        SystemUtilsWrapper systemUtilsWrapper = Mockito.mock(SystemUtilsWrapper.class);
        Mockito.when(systemUtilsWrapper.isOperatingSystemWindows()).thenReturn(isOperatingSystemWindows);

        LdapExtensions ldapExtensions = new LdapExtensions(settings, systemUtilsWrapper);

        List<Class> extensions = ldapExtensions.getExtensions();

        assertThat(extensions).isNotNull();
        assertThat(CollectionUtils.isEqualCollection(extensions, expectedExtensions)).isTrue();
    }

    private List<Class> getExpectedLdapExtensions() {
        List<Class> expectedExtensions = new ArrayList<Class>();
        expectedExtensions.add(LdapRealm.class);
        expectedExtensions.add(LdapSettingsManager.class);
        expectedExtensions.add(LdapAutodiscovery.class);

        return expectedExtensions;
    }

    private List<Class> getExpectedWindowsExtensions() {
        List<Class> expectedExtensions = new ArrayList<Class>();
        expectedExtensions.add(WindowsSecurityRealm.class);
        expectedExtensions.add(WindowsAuthenticationHelper.class);
        expectedExtensions.add(WindowsGroupsProviderFilter.class);
        expectedExtensions.add(WindowsLogoutFilter.class);

        return expectedExtensions;
    }
}
