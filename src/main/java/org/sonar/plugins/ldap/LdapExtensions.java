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

import com.google.common.collect.Lists;
import org.apache.commons.lang.StringUtils;
import org.sonar.api.ExtensionProvider;
import org.sonar.api.ServerExtension;
import org.sonar.api.config.Settings;
import org.sonar.plugins.ldap.windows.WindowsSecurityRealm;

import java.util.List;

public class LdapExtensions extends ExtensionProvider implements ServerExtension {
    static final String SONAR_LDAP_WINDOWS_AUTH = "sonar.ldap.windows.auth";
    static final String DEFAULT_SONAR_LDAP_WINDOWS_AUTH = "true";

    private final Settings settings;
    private final SystemUtilsWrapper systemUtilsWrapper;

    public LdapExtensions(Settings settings) {
        this(settings, new SystemUtilsWrapper());
    }

    LdapExtensions(Settings settings, SystemUtilsWrapper systemUtilsWrapper) {
        this.settings = settings;
        this.systemUtilsWrapper = systemUtilsWrapper;
    }

    @Override
    public Object provide() {
        return getExtensions();
    }

    List<Class> getExtensions() {
        List<Class> extensions = Lists.newArrayList();
        if (isWindowsAuthEnabled()) {
            if (systemUtilsWrapper.isOperatingSystemWindows()) {
                extensions.add(WindowsSecurityRealm.class);
            } else {
                throw new IllegalArgumentException(
                        String.format("Windows authentication is enabled, while the OS is not Windows."));
            }
        } else {
            extensions.add(LdapRealm.class);
            extensions.add(LdapSettingsManager.class);
            extensions.add(LdapAutodiscovery.class);
        }
        return extensions;
    }

    boolean isWindowsAuthEnabled() {
        boolean isWindowsAuthEnabled;
        if (systemUtilsWrapper.isOperatingSystemWindows()) {
            // In Windows OS, Windows authentication is enabled by default.
            isWindowsAuthEnabled = Boolean.parseBoolean(StringUtils.defaultString(settings.getString(SONAR_LDAP_WINDOWS_AUTH),
                    DEFAULT_SONAR_LDAP_WINDOWS_AUTH));
        } else {
            isWindowsAuthEnabled = settings.getBoolean(SONAR_LDAP_WINDOWS_AUTH);
        }

        return isWindowsAuthEnabled;
    }
}
