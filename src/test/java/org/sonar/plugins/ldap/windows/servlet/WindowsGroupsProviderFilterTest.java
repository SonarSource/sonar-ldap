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
package org.sonar.plugins.ldap.windows.servlet;

import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.sonar.plugins.ldap.windows.WindowsAuthenticationHelper;
import org.sonar.plugins.ldap.windows.auth.WindowsPrincipal;
import org.sonar.plugins.ldap.windows.stubs.HttpSessionStub;

import static org.assertj.core.api.Assertions.assertThat;

public class WindowsGroupsProviderFilterTest {
    private WindowsGroupsProviderFilter windowsGroupsProviderFilter;

    @Before
    public void init() {
        windowsGroupsProviderFilter = new WindowsGroupsProviderFilter();
    }

    @Test
    public void doGetPatternTest() {
        assertThat(windowsGroupsProviderFilter.doGetPattern().getUrl()).isEqualTo("/");
    }

    @Test
    public void doFilterTestWindowsPrincipalNotSet() throws IOException, ServletException {
        HttpSessionStub httpSession = new HttpSessionStub();
        HttpServletRequest servletRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(servletRequest.getSession()).thenReturn(httpSession);
        HttpServletResponse servletResponse = Mockito.mock(HttpServletResponse.class);
        FilterChain filterChain = Mockito.mock(FilterChain.class);

        windowsGroupsProviderFilter.doFilter(servletRequest, servletResponse, filterChain);

        Mockito.verify(filterChain, Mockito.times(1)).doFilter(servletRequest, servletResponse);
    }

    @Test
    public void doFilterTestGroupsNotSynchronized() throws IOException, ServletException {
        HttpSessionStub httpSession = new HttpSessionStub();
        httpSession.setAttribute(WindowsAuthenticationHelper.WINDOWS_PRINCIPAL, Mockito.mock(WindowsPrincipal.class));
        HttpServletRequest servletRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(servletRequest.getSession()).thenReturn(httpSession);
        HttpServletResponse servletResponse = Mockito.mock(HttpServletResponse.class);
        FilterChain filterChain = Mockito.mock(FilterChain.class);

        windowsGroupsProviderFilter.doFilter(servletRequest, servletResponse, filterChain);

        boolean isUserGroupSynchronized = (boolean) httpSession.getAttribute(WindowsAuthenticationHelper.USER_GROUPS_SYNCHRONIZED);
        assertThat(isUserGroupSynchronized).isTrue();
        Mockito.verify(servletResponse, Mockito.times(1)).sendRedirect("/ldap/initUserGroups");
        Mockito.verify(filterChain, Mockito.never()).doFilter(servletRequest, servletResponse);
    }

    @Test
    public void doFilterTestGroupsIsSynchronized() throws IOException, ServletException {
        HttpSessionStub httpSession = new HttpSessionStub();
        httpSession.setAttribute(WindowsAuthenticationHelper.WINDOWS_PRINCIPAL, Mockito.mock(WindowsPrincipal.class));
        httpSession.setAttribute(WindowsAuthenticationHelper.USER_GROUPS_SYNCHRONIZED, true);
        HttpServletRequest servletRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(servletRequest.getSession()).thenReturn(httpSession);
        HttpServletResponse servletResponse = Mockito.mock(HttpServletResponse.class);
        FilterChain filterChain = Mockito.mock(FilterChain.class);

        windowsGroupsProviderFilter.doFilter(servletRequest, servletResponse, filterChain);

        Mockito.verify(filterChain, Mockito.times(1)).doFilter(servletRequest, servletResponse);
    }
}
