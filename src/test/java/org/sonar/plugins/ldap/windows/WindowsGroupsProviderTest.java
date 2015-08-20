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

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.NullArgumentException;
import org.junit.Test;
import org.mockito.Mockito;

import java.util.ArrayList;
import java.util.Collection;

import static org.assertj.core.api.Assertions.assertThat;

public class WindowsGroupsProviderTest {

    @Test(expected = NullArgumentException.class)
    public void NullArgumentCheck() {
        WindowsGroupsProvider groupsProvider = new WindowsGroupsProvider(null);
    }

    @Test
    public void doGetGroupsTests() {
        Collection<String> groups = new ArrayList<String>();
        groups.add("group1");

        this.runDoGetGroupsTest(null, new ArrayList<String>());
        this.runDoGetGroupsTest("", new ArrayList<String>());
        this.runDoGetGroupsTest("user", null);
        this.runDoGetGroupsTest("user", new ArrayList<String>());
        this.runDoGetGroupsTest("user", groups);
    }

    private void runDoGetGroupsTest(String userName, Collection<String> expectedGroups) {
        WindowsAuthenticationHelper windowsAuthenticationHelper = Mockito.mock(WindowsAuthenticationHelper.class);
        Mockito.when(windowsAuthenticationHelper.getGroups(userName)).thenReturn(expectedGroups);
        WindowsGroupsProvider groupsProvider = new WindowsGroupsProvider(windowsAuthenticationHelper);

        Collection<String> groups = groupsProvider.doGetGroups(userName);

        if (expectedGroups == null) {
            assertThat(groups).isNull();
        } else {
            assertThat(groups).isNotNull();
            assertThat(CollectionUtils.isEqualCollection(groups, expectedGroups)).isTrue();
        }
    }
}
