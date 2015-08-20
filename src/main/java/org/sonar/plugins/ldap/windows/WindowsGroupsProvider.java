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
import org.sonar.api.security.ExternalGroupsProvider;

import java.util.ArrayList;
import java.util.Collection;

public class WindowsGroupsProvider extends ExternalGroupsProvider {
    private static final Logger LOG = LoggerFactory.getLogger(WindowsGroupsProvider.class);

    private final WindowsAuthenticationHelper windowsAuthenticationHelper;

    public WindowsGroupsProvider(WindowsAuthenticationHelper windowsAuthenticationHelper) {
        if (windowsAuthenticationHelper == null) {
            throw new NullArgumentException("windowsAuthenticationHelper");
        }
        this.windowsAuthenticationHelper = windowsAuthenticationHelper;
    }

    /**
     * @return A {@link Collection} of groups for specified user
     */
    @Override
    public Collection<String> doGetGroups(final String userName) {
        if (userName == null || userName.isEmpty()) {
            LOG.debug("Username is blank.");
            return new ArrayList<String>();
        }
        LOG.debug("Requesting groups for user: {}", userName);

        return windowsAuthenticationHelper.getGroups(userName);
    }
}
