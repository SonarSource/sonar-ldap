/*
 * Sonar LDAP Plugin
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
package org.sonar.plugins.ldap;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.api.security.ExternalUsersProvider.Context;
import org.sonar.api.utils.SonarException;
import org.sonar.api.web.ServletFilter;


/**
 * Filter that redirects to pre-authentication filter when the user isn't logged in,
 * pre-authentication is enabled and the user exists in LDAP.
 */
public class AutomaticLoginFilter extends ServletFilter {

  private static final Logger LOGGER = LoggerFactory.getLogger(AutomaticLoginFilter.class);

  private final PreAuthHelper preAuthHelper;
  private final LdapRealm ldapRealm;

  public AutomaticLoginFilter(PreAuthHelper preAuthHelper, LdapRealm ldapRealm) {
    this.preAuthHelper = preAuthHelper;
    this.ldapRealm = ldapRealm;
  }

  public void init(FilterConfig filterConfig) throws ServletException {
  }

  @Override
  public UrlPattern doGetPattern() {
    return UrlPattern.create("/");
  }

  public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain)
      throws IOException, ServletException {

    HttpServletRequest httpServletRequest = (HttpServletRequest) request;
    HttpServletResponse httpServletResponse = (HttpServletResponse) response;
    
    if (!preAuthHelper.isPreAuthRequired(httpServletRequest)) {
      // If not preauth or already logged in just continue
      filterChain.doFilter(httpServletRequest, response);
      return;
    }

    if (StringUtils.isBlank(preAuthHelper.findPreAuthenticatedUser(httpServletRequest))) {
      LOGGER.warn("Could not find any pre-authenticated user in Header: "
          + preAuthHelper.getPreAuthHeaderName());
      filterChain.doFilter(httpServletRequest, response);
      return;
    }

    String user = preAuthHelper.findPreAuthenticatedUser(httpServletRequest);
    try {
      // Verify that user exists in ldap otherwise we run into a redirect loop
      ldapRealm.getUsersProvider().doGetUserDetails(new Context(user, httpServletRequest));
      LOGGER.debug("No session available. Redirecting to pre-authentication...");
      httpServletResponse.sendRedirect(httpServletRequest.getContextPath() + "/ldap/authenticate");
    } catch (SonarException se) {
      LOGGER.warn("Pre-authenticated user could not be found in LDAP: " + user);
      filterChain.doFilter(httpServletRequest, response);
    }
  }

  public void destroy() {
  }

}
