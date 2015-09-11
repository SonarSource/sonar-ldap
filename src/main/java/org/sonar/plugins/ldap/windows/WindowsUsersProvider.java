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

import org.apache.commons.lang.NullArgumentException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.api.security.ExternalUsersProvider;
import org.sonar.api.security.UserDetails;

public class WindowsUsersProvider extends ExternalUsersProvider {
    private static final Logger LOG = LoggerFactory.getLogger(WindowsUsersProvider.class);
    private final WindowsAuthenticationHelper windowsAuthenticationHelper;

    public WindowsUsersProvider(WindowsAuthenticationHelper windowsAuthenticationHelper) {
        if (windowsAuthenticationHelper == null) {
            throw new NullArgumentException("windowsAuthenticationHelper");
        }
        this.windowsAuthenticationHelper = windowsAuthenticationHelper;
    }

    /**
     * @return details for the user specified in {@link Context}, or null if the user doesn't exist
     */
    @Override
    public UserDetails doGetUserDetails(Context context) {
        final String userName = context.getUsername();
        if (userName == null || userName.isEmpty()) {
            LOG.debug("Username is blank.");
            return null;
        }
        LOG.debug("Requesting details for user: {}", userName);

        return windowsAuthenticationHelper.getUserDetails(userName);
    }
}
