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
package org.sonar.plugins.ldap.windows.sso.servlet;

import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.sonar.api.config.Settings;
import org.sonar.plugins.ldap.windows.WindowsAuthenticationHelper;
import org.sonar.plugins.ldap.windows.auth.WindowsAuthSettings;
import org.sonar.plugins.ldap.windows.sso.WaffleSettings;
import waffle.servlet.NegotiateSecurityFilter;

import static org.assertj.core.api.Assertions.assertThat;

public class SsoAuthenticationFilterTest {
  private SsoAuthenticationFilter ssoAuthenticationFilter;
  private WindowsAuthenticationHelper windowsAuthenticationHelper;
  private WindowsAuthSettings windowsAuthSettings;
  private NegotiateSecurityFilter negotiateSecurityFilter;
  private FilterChain ssoFilterChain;

  @Before
  public void init() {
    windowsAuthSettings = new WindowsAuthSettings(new Settings());
    windowsAuthenticationHelper = Mockito.mock(WindowsAuthenticationHelper.class);
    negotiateSecurityFilter = Mockito.mock(NegotiateSecurityFilter.class);
    ssoFilterChain = Mockito.mock(FilterChain.class);
    ssoAuthenticationFilter = new SsoAuthenticationFilter(windowsAuthSettings, windowsAuthenticationHelper,
      negotiateSecurityFilter, ssoFilterChain);
  }

  @Test
  public void doGetPatternTest() {
    assertThat(ssoAuthenticationFilter.doGetPattern().getUrl()).isEqualTo("/sessions/new");
  }

  @Test
  public void initTest() throws ServletException {
    FilterConfig filterConfig = Mockito.mock(FilterConfig.class);

    ssoAuthenticationFilter.init(filterConfig);

    Mockito.verify(filterConfig, Mockito.times(1)).getServletContext();
    Mockito.verify(negotiateSecurityFilter, Mockito.times(1)).init(Mockito.any(WaffleSettings.class));
  }

  @Test
  public void destroyTest() {
    ssoAuthenticationFilter.destroy();
    Mockito.verify(negotiateSecurityFilter, Mockito.times(1)).destroy();
  }

  @Test
  public void doFilterTest() throws IOException, ServletException {
    runDoFilterTest(true, true);
    runDoFilterTest(false, true);
    runDoFilterTest(false, false);
    runDoFilterTest(true, false);
  }

  @Test
  public void doNegotiateSecurityFilterTest() throws IOException, ServletException {
    runDoNegotiateSecurityFilterTest(true, true);
    runDoNegotiateSecurityFilterTest(false, true);
    runDoNegotiateSecurityFilterTest(false, false);
    runDoNegotiateSecurityFilterTest(true, false);
  }

  private void runDoFilterTest(boolean isUserAuthenticated, boolean isRequestForMixedModeAuth) throws IOException, ServletException {

    HttpSession httpSession = Mockito.mock(HttpSession.class);
    HttpServletRequest servletRequest = Mockito.mock(HttpServletRequest.class);
    Mockito.when(servletRequest.getSession()).thenReturn(httpSession);
    Mockito.when(servletRequest.getParameter("mixedmode")).thenReturn(Boolean.toString(isRequestForMixedModeAuth));

    HttpServletResponse servletResponse = Mockito.mock(HttpServletResponse.class);

    FilterChain filterChain = Mockito.mock(FilterChain.class);

    Mockito.when(windowsAuthenticationHelper.isUserSsoAuthenticated(servletRequest)).thenReturn(isUserAuthenticated);

    ssoAuthenticationFilter.doFilter(servletRequest, servletResponse, filterChain);

    if (isUserAuthenticated || isRequestForMixedModeAuth) {
      Mockito.verify(filterChain, Mockito.times(1)).doFilter(servletRequest, servletResponse);
    } else {
      Mockito.verify(negotiateSecurityFilter, Mockito.times(1)).doFilter(servletRequest, servletResponse, ssoFilterChain);
    }

  }

  private void runDoNegotiateSecurityFilterTest(boolean isUserAuthenticated, boolean isResponseCommitted) throws IOException, ServletException {

    HttpSession httpSession = Mockito.mock(HttpSession.class);
    HttpServletRequest servletRequest = Mockito.mock(HttpServletRequest.class);
    Mockito.when(servletRequest.getSession()).thenReturn(httpSession);

    HttpServletResponse servletResponse = Mockito.mock(HttpServletResponse.class);
    Mockito.when(servletResponse.isCommitted()).thenReturn(isResponseCommitted);

    FilterChain filterChain = Mockito.mock(FilterChain.class);

    Mockito.when(windowsAuthenticationHelper.isUserSsoAuthenticated(servletRequest)).thenReturn(isUserAuthenticated);

    ssoAuthenticationFilter.doNegotiateSecurityFilter(servletRequest, servletResponse, filterChain);

    if (!isResponseCommitted) {
      if (isUserAuthenticated) {
        Mockito.verify(servletResponse, Mockito.times(1)).sendRedirect("/ldap/validate");
      } else {
        Mockito.verify(filterChain, Mockito.times(1)).doFilter(servletRequest, servletResponse);
      }
    } else {
      Mockito.verify(servletResponse, Mockito.times(0)).sendRedirect("/ldap/validate");
      Mockito.verify(filterChain, Mockito.times(0)).doFilter(servletRequest, servletResponse);
    }
  }
}
