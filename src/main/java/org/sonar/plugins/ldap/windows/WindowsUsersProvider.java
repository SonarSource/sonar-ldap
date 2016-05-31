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

import org.apache.commons.lang.StringUtils;
import org.sonar.api.security.ExternalUsersProvider;
import org.sonar.api.security.UserDetails;
import org.sonar.api.utils.log.Logger;
import org.sonar.api.utils.log.Loggers;

import static com.google.common.base.Preconditions.checkNotNull;

public class WindowsUsersProvider extends ExternalUsersProvider {
  private static final Logger LOG = Loggers.get(WindowsUsersProvider.class);

  private final WindowsAuthenticationHelper windowsAuthenticationHelper;

  public WindowsUsersProvider(WindowsAuthenticationHelper windowsAuthenticationHelper) {
    checkNotNull(windowsAuthenticationHelper, "null windowsAuthenticationHelper");
    this.windowsAuthenticationHelper = windowsAuthenticationHelper;
  }

  /**
   * @return details for the user specified in {@link Context}, or null if the user doesn't exist
   */
  @Override
  public UserDetails doGetUserDetails(Context context) {
    UserDetails userDetails;

    final String userName = context.getUsername();
    if (StringUtils.isBlank(userName)) {
      userDetails = windowsAuthenticationHelper.getSsoUserDetails(context.getRequest());
    } else {
      LOG.debug("Requesting details for user: {}", userName);
      userDetails = windowsAuthenticationHelper.getUserDetails(userName);
    }

    return userDetails;
  }
}
