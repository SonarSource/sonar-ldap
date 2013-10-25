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
import java.util.Map;

import javax.naming.NamingException;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchResult;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.api.security.Authenticator;

/**
 * @author Evgeny Mandrikov
 */
public class LdapAuthenticator extends Authenticator {

  private static final Logger LOG = LoggerFactory.getLogger(LdapAuthenticator.class);
  private final Map<String, LdapContextFactory> contextFactories;
  private final Map<String, LdapUserMapping> userMappings;

  public LdapAuthenticator(Map<String, LdapContextFactory> contextFactories, Map<String, LdapUserMapping> userMappings) {
    this.contextFactories = contextFactories;
    this.userMappings = userMappings;
  }

  /** 
   * Authenticate the user against LDAP servers until first success.
   * @param context the authentication context
   * @return false if specified user cannot be authenticated with specified password on any LDAP server
   */
  @Override
  public boolean doAuthenticate(Context context) {
    for (String ldapKey : userMappings.keySet()) {
      LdapContextFactory ldapContextFactory = contextFactories.get(ldapKey);
      final String principal = determinePrincipal(context, ldapKey, ldapContextFactory);
      if (principal == null) {
        continue;
      }
      
      boolean passwordValid;
      if (ldapContextFactory.isPreAuth()) {
        LOG.debug("User " + principal + " was preauthenticated.");
        passwordValid = true;
      } else if (ldapContextFactory.isGssapi()) {
        LOG.debug("Checking Password through GSSAPI");
        passwordValid = checkPasswordUsingGssapi(principal, context.getPassword(), ldapKey);
      } else {
        LOG.debug("Checking Password through SASL");
        passwordValid = checkPasswordUsingBind(principal, context.getPassword(), ldapKey);
      }
      if (passwordValid) {
        LOG.debug("Successfully authenticated!");
          return true;
      }
    }
    LOG.debug("User {} not found", context.getUsername());
    return false;
  }

  private String determinePrincipal(Context context,
      String ldapKey,
      LdapContextFactory ldapContextFactory) {
    
    if (ldapContextFactory.isPreAuth()) {
      return findPreAuthenticatedUser(context.getRequest(), ldapContextFactory.getPreAuthHeaderName());
          
    } else if (ldapContextFactory.isSasl()) {
      return context.getUsername();
      
    } else {
      // Simple auth
      final SearchResult result;
      try {
        result = userMappings.get(ldapKey).createSearch(ldapContextFactory, context.getUsername()).findUnique();
      } catch (NamingException e) {
        LOG.debug("User {} not found in server {}: {}", new Object[] {context.getUsername(), ldapKey, e.getMessage()});
        return null;
      }
      if (result == null) {
        LOG.debug("User {} not found in " + ldapKey, context.getUsername());
        return null;
      }
      return result.getNameInNamespace();
    }
  }

  private String findPreAuthenticatedUser(HttpServletRequest request, String preAuthHeaderName) {
    String userNameFromHeader = request.getHeader(preAuthHeaderName);
    if (userNameFromHeader == null) {
      LOG.debug("Preauthentication Header " + preAuthHeaderName + " not found.");
      logAvailableHeaders(request);
      return userNameFromHeader;
    }
    LOG.debug("Found preauthenticated user " + userNameFromHeader + " in header " + preAuthHeaderName);
    return userNameFromHeader;
  }

  private void logAvailableHeaders(HttpServletRequest request) {
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

  private boolean checkPasswordUsingBind(String principal, String password, String ldapKey) {
    if (StringUtils.isEmpty(password)) {
      LOG.debug("Password is blank.");
      return false;
    }
    InitialDirContext context = null;
    try {
      context = contextFactories.get(ldapKey).createUserContext(principal, password);
      return true;
    } catch (NamingException e) {
      LOG.debug("Password not valid for user {} in server {}: {}", new Object[] {principal, ldapKey, e.getMessage()});
      return false;
    } finally {
      ContextHelper.closeQuetly(context);
    }
  }

  private boolean checkPasswordUsingGssapi(String principal, String password, String ldapKey) {
    // Use our custom configuration to avoid reliance on external config
    Configuration.setConfiguration(new Krb5LoginConfiguration());
    LoginContext lc;
    try {
      lc = new LoginContext(getClass().getName(), new CallbackHandlerImpl(principal, password));
      lc.login();
    } catch (LoginException e) {
      // Bad username: Client not found in Kerberos database
      // Bad password: Integrity check on decrypted field failed
      LOG.debug("Password not valid for {} in server {}: {}", new Object[] {principal, ldapKey, e.getMessage()});
      return false;
    }
    try {
      lc.logout();
    } catch (LoginException e) {
      LOG.warn("Logout fails", e);
    }
    return true;
  }

}
