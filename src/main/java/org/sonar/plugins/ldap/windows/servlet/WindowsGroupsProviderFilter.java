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
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.sonar.api.web.ServletFilter;
import org.sonar.plugins.ldap.windows.WindowsAuthenticationHelper;
import org.sonar.plugins.ldap.windows.auth.WindowsPrincipal;

/**
 * A Windows User-groups provider filter
 */
public class WindowsGroupsProviderFilter extends ServletFilter {

    @Override
    public UrlPattern doGetPattern() {
        return UrlPattern.create("/");
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        // Do nothing
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;
        HttpSession session = request.getSession();

        WindowsPrincipal windowsPrincipal = (WindowsPrincipal) session.getAttribute(WindowsAuthenticationHelper.WINDOWS_PRINCIPAL);
        if (windowsPrincipal != null && session.getAttribute(WindowsAuthenticationHelper.USER_GROUPS_SYNCHRONIZED) == null) {
            session.setAttribute(WindowsAuthenticationHelper.USER_GROUPS_SYNCHRONIZED, Boolean.TRUE);
            response.sendRedirect("/ldap/initUserGroups");
        } else {
            filterChain.doFilter(servletRequest, servletResponse);
        }
    }

    @Override
    public void destroy() {
        // Do nothing
    }
}
