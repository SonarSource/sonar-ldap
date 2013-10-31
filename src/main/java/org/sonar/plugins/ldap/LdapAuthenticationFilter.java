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
import org.sonar.api.config.Settings;
import org.sonar.api.security.UserDetails;
import org.sonar.api.web.ServletFilter;


public class LdapAuthenticationFilter extends ServletFilter {
  
  private static final Logger LOGGER = LoggerFactory.getLogger(LdapAuthenticationFilter.class);

  static final String USER_ATTRIBUTE = "preauth_user";
  private final static String DEFAULT_PRE_AUTH_HEADER_NAME = "REMOTE_USER";
  private final Settings settings;
  
  public LdapAuthenticationFilter(Settings settings) {
    this.settings = settings;
  }

  public void init(FilterConfig filterConfig) throws ServletException {
  }
  
  @Override
  public UrlPattern doGetPattern() {
    return UrlPattern.create("/sessions/new");
  }

  public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain)
      throws IOException, ServletException {
    
    LOGGER.debug("Triggered LdapAuthenticationFilter...");
    HttpServletRequest httpServletRequest = (HttpServletRequest) request;
    HttpServletResponse httpServletResponse = (HttpServletResponse) response;
    
    
    String preAuthHeaderName = StringUtils.defaultString(settings.getString("ldap.preAuthHeaderName"), DEFAULT_PRE_AUTH_HEADER_NAME);
    
    
    String userName = httpServletRequest.getHeader(preAuthHeaderName);
    if (userName == null) {
      LOGGER.debug("HTTP Header " + preAuthHeaderName + " not found.");
      httpServletResponse.sendRedirect("/ldap/unauthorized");
    } else {
      LOGGER.debug("User " + userName+ " was preauthenticated.");
      UserDetails user = new UserDetails();
      user.setName(userName);
      request.setAttribute(USER_ATTRIBUTE, user);
      httpServletResponse.sendRedirect("/ldap/validate");
    }
  }
  
  
  
  public void destroy() {
  }

}
