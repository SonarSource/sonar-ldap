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
package org.sonar.plugins.ldap.windows;

import javax.annotation.ParametersAreNonnullByDefault;
import org.apache.commons.lang.NullArgumentException;
import org.apache.commons.lang.StringUtils;
import org.sonar.api.security.Authenticator;
import waffle.servlet.WindowsPrincipal;

public class WindowsAuthenticator extends Authenticator {
  private final WindowsAuthenticationHelper windowsAuthenticationHelper;

  public WindowsAuthenticator(WindowsAuthenticationHelper windowsAuthenticationHelper) {
    if (windowsAuthenticationHelper == null) {
      throw new NullArgumentException("windowsAuthenticationHelper");
    }
    this.windowsAuthenticationHelper = windowsAuthenticationHelper;
  }

  @Override
  @ParametersAreNonnullByDefault
  public boolean doAuthenticate(Context context) {
    boolean isUserAuthenticated = false;

    final String userName = context.getUsername();
    final String password = context.getPassword();

    // Cleanup basic auth windows principal from HttpSession
    windowsAuthenticationHelper.removeWindowsPrincipalForBasicAuth(context.getRequest());

    if (StringUtils.isNotBlank(userName) && StringUtils.isNotBlank(password)) {
      // Cleanup Windows Principal for sso only in case we are doing basic auth
      windowsAuthenticationHelper.removeWindowsPrincipalForSso(context.getRequest());
      WindowsPrincipal windowsPrincipal = windowsAuthenticationHelper.logonUser(userName, password);
      if (windowsPrincipal != null) {
        isUserAuthenticated = true;
        windowsAuthenticationHelper.setWindowsPrincipalForBasicAuth(context.getRequest(), windowsPrincipal);
      }
    } else {
      isUserAuthenticated = windowsAuthenticationHelper.isUserSsoAuthenticated(context.getRequest());
    }

    return isUserAuthenticated;
  }
}
