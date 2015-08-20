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
import org.sonar.api.security.LoginPasswordAuthenticator;

public class WindowsAuthenticator implements LoginPasswordAuthenticator {
    private static final Logger LOG = LoggerFactory.getLogger(WindowsAuthenticator.class);
    private final WindowsAuthenticationHelper windowsAuthenticationHelper;

    public WindowsAuthenticator(WindowsAuthenticationHelper windowsAuthenticationHelper) {
        if (windowsAuthenticationHelper == null) {
            throw new NullArgumentException("windowsAuthenticationHelper");
        }
        this.windowsAuthenticationHelper = windowsAuthenticationHelper;
    }

    @Override
    public void init() {
        // nothing to do
    }

    /**
     * Authenticates the user using Windows LogonUser API
     *
     * @param userName The username to use.
     * @param password The password to use.
     */
    @Override
    public boolean authenticate(final String userName, final String password) {
        if (userName == null || userName.isEmpty()) {
            LOG.debug("Username is blank.");
            return false;
        }

        if (password == null || password.isEmpty()) {
            LOG.debug("Password is blank.");
            return false;
        }

        LOG.debug("Authenticating user: {}", userName);
        return windowsAuthenticationHelper.logonUser(userName, password);
    }
}
