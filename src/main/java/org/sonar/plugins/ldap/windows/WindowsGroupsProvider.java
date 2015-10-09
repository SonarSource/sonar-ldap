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
package org.sonar.plugins.ldap.windows;

import java.util.Collection;
import javax.annotation.ParametersAreNonnullByDefault;
import org.apache.commons.lang.NullArgumentException;
import org.sonar.api.security.ExternalGroupsProvider;
import waffle.servlet.WindowsPrincipal;

public class WindowsGroupsProvider extends ExternalGroupsProvider {
  private final WindowsAuthenticationHelper windowsAuthenticationHelper;

  public WindowsGroupsProvider(WindowsAuthenticationHelper windowsAuthenticationHelper) {
    if (windowsAuthenticationHelper == null) {
      throw new NullArgumentException("windowsAuthenticationHelper");
    }
    this.windowsAuthenticationHelper = windowsAuthenticationHelper;
  }

  /**
   * Retrieves the group information for the user.
   *
   * @return A {@link Collection} of groups the user is member of.
   */
  @ParametersAreNonnullByDefault
  @Override
  public Collection<String> doGetGroups(Context context) {
    WindowsPrincipal windowsPrincipal = windowsAuthenticationHelper.getWindowsPrincipal(context.getRequest(),
            WindowsAuthenticationHelper.BASIC_AUTH_PRINCIPAL_KEY) ;
    if (windowsPrincipal == null) {
      windowsPrincipal = windowsAuthenticationHelper.getWindowsPrincipal(context.getRequest(),
              WindowsAuthenticationHelper.SSO_PRINCIPAL_KEY);
    }

    return windowsPrincipal != null ? windowsAuthenticationHelper.getUserGroups(windowsPrincipal) : null;
  }
}
