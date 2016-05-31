/*
 * SonarQube LDAP Plugin
 * Copyright (C) 2009-2016 SonarSource SA
 * mailto:contact AT sonarsource DOT com
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
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
package org.sonar.plugins.ldap;

import java.util.Arrays;
import java.util.List;
import org.apache.commons.lang.StringUtils;
import org.sonar.api.ExtensionProvider;
import org.sonar.api.ServerExtension;
import org.sonar.api.config.Settings;
import org.sonar.api.utils.System2;
import org.sonar.plugins.ldap.windows.WindowsAuthenticationHelper;
import org.sonar.plugins.ldap.windows.WindowsSecurityRealm;
import org.sonar.plugins.ldap.windows.auth.WindowsAuthSettings;
import org.sonar.plugins.ldap.windows.auth.servlet.WindowsLogoutFilter;
import org.sonar.plugins.ldap.windows.sso.servlet.SsoAuthenticationFilter;
import org.sonar.plugins.ldap.windows.sso.servlet.SsoValidationFilter;

public class LdapExtensions extends ExtensionProvider implements ServerExtension {
  private final Settings settings;
  private final System2 system2;

  public LdapExtensions(Settings settings) {
    this(settings, new System2());
  }

  LdapExtensions(Settings settings, System2 system2) {
    this.settings = settings;
    this.system2 = system2;
  }

  @Override
  public Object provide() {
    return getExtensions();
  }

  List<Class<?>> getExtensions() {
    if (isWindowsAuthEnabled()) {
      if (!system2.isOsWindows()) {
        throw new IllegalArgumentException("Windows authentication is enabled, while the OS is not Windows.");
      }
      return getWindowsAuthExtensions();
    }
    return getLdapExtensions();
  }

  private boolean isWindowsAuthEnabled() {
    boolean isWindowsAuthEnabled;
    if (system2.isOsWindows()) {
      // In Windows OS, Windows authentication is enabled by default.
      isWindowsAuthEnabled = Boolean.parseBoolean(StringUtils.defaultString(
        settings.getString(WindowsAuthSettings.LDAP_WINDOWS_AUTH),
        WindowsAuthSettings.DEFAULT_SONAR_LDAP_WINDOWS_AUTH));
    } else {
      isWindowsAuthEnabled = settings.getBoolean(WindowsAuthSettings.LDAP_WINDOWS_AUTH);
    }

    return isWindowsAuthEnabled;
  }

  private List<Class<?>> getWindowsAuthExtensions() {
    return Arrays.asList(
      WindowsSecurityRealm.class,
      WindowsAuthenticationHelper.class,
      WindowsAuthSettings.class,
      SsoAuthenticationFilter.class,
      SsoValidationFilter.class,
      WindowsLogoutFilter.class);
  }

  private List<Class<?>> getLdapExtensions() {
    return Arrays.asList(LdapRealm.class, LdapSettingsManager.class, LdapAutodiscovery.class);
  }
}
