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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.api.web.ServletFilter;


/**
 * Filter that triggers the login of the user that is defined by the pre-authentication header.
 */
public class PreAuthenticationFilter extends ServletFilter {
  
  /** Name of the attribute that contains the username.
   * This key is also used by the ruby ldap controller. */
  private static final String PREAUTH_USER_ATTRIBUTE = "preauth_user";

  private static final Logger LOGGER = LoggerFactory.getLogger(PreAuthenticationFilter.class);
  
  private final PreAuthHelper preAuthHelper;
  
  public PreAuthenticationFilter(PreAuthHelper preAuthHelper) {
    this.preAuthHelper = preAuthHelper;
  }

  public void init(FilterConfig filterConfig) throws ServletException {
  }
  
  @Override
  public UrlPattern doGetPattern() {
    return UrlPattern.create("/ldap/authenticate");
  }

  public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain)
      throws IOException, ServletException {
    
    HttpServletRequest httpServletRequest = (HttpServletRequest) request;
    if (preAuthHelper.isPreAuthRequired(httpServletRequest)) {
      String user = preAuthHelper.findPreAuthenticatedUser(httpServletRequest);
      LOGGER.debug("Found preauthenticated user: " + user);
      httpServletRequest.setAttribute(PREAUTH_USER_ATTRIBUTE, user);
    }
    filterChain.doFilter(httpServletRequest, response);
  }
  
  public void destroy() {
  }

}
