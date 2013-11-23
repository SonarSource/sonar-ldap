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

import java.util.Enumeration;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.BooleanUtils;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.api.ServerExtension;
import org.sonar.api.config.Settings;

import com.google.common.annotations.VisibleForTesting;


public class PreAuthHelper implements ServerExtension {


  private static final Logger LOG = LoggerFactory.getLogger(PreAuthHelper.class);

  @VisibleForTesting
  static final String LDAP_PRE_AUTH_HEADER_NAME_KEY = "ldap.preAuthHeaderName";
  @VisibleForTesting
  static final String LDAP_PREAUTHENTICATION_KEY = "ldap.preauthentication";
  @VisibleForTesting
  static final String DEFAULT_PRE_AUTH_HEADER_NAME = "REMOTE_USER";

  private final boolean preAuthentication;
  private final String preAuthHeaderName;

  public PreAuthHelper(Settings settings) {
    this.preAuthentication = BooleanUtils.toBoolean(settings.getString(LDAP_PREAUTHENTICATION_KEY));
    this.preAuthHeaderName = StringUtils.defaultString(
        settings.getString(LDAP_PRE_AUTH_HEADER_NAME_KEY), DEFAULT_PRE_AUTH_HEADER_NAME);
  }

  public boolean isPreAuth() {
    return preAuthentication;
  }

  public String getPreAuthHeaderName() {
    return preAuthHeaderName;
  }

  public boolean isPreAuthRequired(HttpServletRequest request) {
    return isPreAuth() && request.getSession(false) == null;
  }

  /**
   * Finds the name of the preauthenticated user.
   * 
   * @param request the {@link HttpServletRequest}
   * @return the name of the preauthenticated user or <code>null</code>
   */
  public String findPreAuthenticatedUser(HttpServletRequest request) {
    String userNameFromHeader = request.getHeader(preAuthHeaderName);
    if (userNameFromHeader == null) {
      LOG.info("Preauthentication Header " + preAuthHeaderName + " not found.");
      logAvailableHeaders(request);
    }
    return userNameFromHeader;
  }

  private void logAvailableHeaders(HttpServletRequest request) {
    if (!LOG.isDebugEnabled()) {
      return;
    }
    StringBuilder sb = new StringBuilder("Available Headers: ");
    Enumeration<String> headerNames = request.getHeaderNames();
    while (headerNames.hasMoreElements()) {
      sb.append(headerNames.nextElement());
      if (headerNames.hasMoreElements()) {
        sb.append(", ");
      }
    }
    LOG.debug(sb.toString());
  }


}
