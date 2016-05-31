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
package org.sonar.plugins.ldap.windows.sso.servlet;

import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.sonar.api.utils.log.Logger;
import org.sonar.api.utils.log.Loggers;
import org.sonar.api.web.ServletFilter;
import org.sonar.plugins.ldap.windows.WindowsAuthenticationHelper;
import org.sonar.plugins.ldap.windows.auth.WindowsAuthSettings;
import org.sonar.plugins.ldap.windows.sso.WaffleSettings;
import waffle.servlet.NegotiateSecurityFilter;

public class SsoAuthenticationFilter extends ServletFilter {
  private final WindowsAuthSettings windowsAuthSettings;
  private final WindowsAuthenticationHelper authenticationHelper;
  private final NegotiateSecurityFilter negotiateSecurityFilter;
  private final FilterChain ssoFilterChain;

  private static final Logger LOG = Loggers.get(SsoAuthenticationFilter.class);

  public SsoAuthenticationFilter(WindowsAuthSettings windowsAuthSettings, WindowsAuthenticationHelper authenticationHelper) {

    this(windowsAuthSettings, authenticationHelper, new NegotiateSecurityFilter(), new FilterChain() {
      @Override
      public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse)
        throws IOException, ServletException {
        // do nothing
      }
    });
  }

  // Using this constructor for testing purpose
  SsoAuthenticationFilter(WindowsAuthSettings windowsAuthSettings, WindowsAuthenticationHelper authenticationHelper,
    NegotiateSecurityFilter negotiateSecurityFilter, FilterChain ssoFilterChain) {
    this.windowsAuthSettings = windowsAuthSettings;
    this.authenticationHelper = authenticationHelper;
    this.negotiateSecurityFilter = negotiateSecurityFilter;
    this.ssoFilterChain = ssoFilterChain;
  }

  @Override
  public ServletFilter.UrlPattern doGetPattern() {
    return ServletFilter.UrlPattern.create("/sessions/new");
  }

  @Override
  public void init(FilterConfig filterConfig) throws ServletException {
    negotiateSecurityFilter.init(new WaffleSettings("NegotiateSecurityFilter", filterConfig.getServletContext(),
      windowsAuthSettings));
  }

  @Override
  public void destroy() {
    negotiateSecurityFilter.destroy();
  }

  @Override
  public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse,
    FilterChain filterChain) throws IOException, ServletException {
    HttpServletRequest request = (HttpServletRequest) servletRequest;
    HttpServletResponse response = (HttpServletResponse) servletResponse;

    if (authenticationHelper.isUserSsoAuthenticated(request)) {
      filterChain.doFilter(request, response);
    } else {
      doNegotiateSecurityFilter(servletRequest, servletResponse, filterChain);
    }
  }

  void doNegotiateSecurityFilter(ServletRequest servletRequest, ServletResponse servletResponse,
    FilterChain filterChain) throws IOException, ServletException {
    HttpServletRequest request = (HttpServletRequest) servletRequest;
    HttpServletResponse response = (HttpServletResponse) servletResponse;

    negotiateSecurityFilter.doFilter(servletRequest, servletResponse, ssoFilterChain);
    if (!response.isCommitted()) {
      if (authenticationHelper.isUserSsoAuthenticated(request)) {
        LOG.debug("Validating authenticated user");
        response.sendRedirect("/ldap/validate");
      } else {
        filterChain.doFilter(request, response);
      }
    }
  }
}
