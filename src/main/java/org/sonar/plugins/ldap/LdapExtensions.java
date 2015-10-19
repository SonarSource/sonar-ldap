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

  List<Class> getExtensions() {
    List<Class> extensions = Lists.newArrayList();
    if (isWindowsAuthEnabled()) {
      if (system2.isOsWindows()) {
        extensions.addAll(getWindowsAuthExtensions());
      } else {
        throw new IllegalArgumentException("Windows authentication is enabled, while the OS is not Windows.");
      }
    } else {
      extensions.addAll(getLdapExtensions());
    }

    return extensions;
  }

  private boolean isWindowsAuthEnabled() {
    boolean isWindowsAuthEnabled;
    if (system2.isOsWindows()) {
      // In Windows OS, Windows authentication is enabled by default.
      isWindowsAuthEnabled = Boolean.parseBoolean(StringUtils.defaultString(
        settings.getString(WindowsAuthSettings.SONAR_WINDOWS_AUTH),
        WindowsAuthSettings.DEFAULT_SONAR_LDAP_WINDOWS_AUTH));
    } else {
      isWindowsAuthEnabled = settings.getBoolean(WindowsAuthSettings.SONAR_WINDOWS_AUTH);
    }

    return isWindowsAuthEnabled;
  }

  private List<Class> getWindowsAuthExtensions() {
    List<Class> extensions = Lists.newArrayList();
    extensions.add(WindowsSecurityRealm.class);
    extensions.add(WindowsAuthenticationHelper.class);
    extensions.add(WindowsAuthSettings.class);
    extensions.add(SsoAuthenticationFilter.class);
    extensions.add(SsoValidationFilter.class);
    extensions.add(WindowsLogoutFilter.class);

    return extensions;
  }

  private List<Class> getLdapExtensions() {
    List<Class> extensions = Lists.newArrayList();
    extensions.add(LdapRealm.class);
    extensions.add(LdapSettingsManager.class);
    extensions.add(LdapAutodiscovery.class);

    return extensions;
  }
}
