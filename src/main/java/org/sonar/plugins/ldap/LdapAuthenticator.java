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

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.api.security.LoginPasswordAuthenticator;

import javax.naming.NamingException;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchResult;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.util.List;
import java.util.Map;

/**
 * @author Evgeny Mandrikov
 */
public class LdapAuthenticator implements LoginPasswordAuthenticator {

  private static final Logger LOG = LoggerFactory.getLogger(LdapAuthenticator.class);

  private final Map<String, LdapContextFactory> contextFactories;
  private final Map<String, LdapUserMapping> userMappings;

  public LdapAuthenticator(Map<String, LdapContextFactory> contextFactories, Map<String, LdapUserMapping> userMappings) {
    this.contextFactories = contextFactories;
    this.userMappings = userMappings;
  }

  public void init() {
    // nothing to do
  }

  /**
   * @return false if specified user cannot be authenticated with specified password
   */
  public boolean authenticate(String login, String password) {
      for(String ldapIndex : userMappings.keySet()){
    final String principal;
    if (contextFactories.get(ldapIndex).isSasl()) {
      principal = login;
    } else {
      final SearchResult result;
      try {
        result = userMappings.get(ldapIndex).createSearch(contextFactories.get(ldapIndex), login).findUnique();
      } catch (NamingException e) {
        LOG.debug("User {} not found in " + ldapIndex + ": {}", login, e.getMessage());
        continue;
      }
      if (result == null) {
        LOG.debug("User {} not found in " + ldapIndex, login);
        continue;
      }
      principal = result.getNameInNamespace();
    }
          boolean passwordValid = false;
    if (contextFactories.get(ldapIndex).isGssapi()) {
      passwordValid = checkPasswordUsingGssapi(principal, password,ldapIndex);
    }
    passwordValid = checkPasswordUsingBind(principal, password,ldapIndex);
          if(passwordValid){
              return true;
          }
    }
      LOG.debug("User {} not found", login);
      return false;
  }

  private boolean checkPasswordUsingBind(String principal, String password,String ldapIndex) {
    if (StringUtils.isEmpty(password)) {
      LOG.debug("Password is blank.");
      return false;
    }
    InitialDirContext context = null;
    try {
      context = contextFactories.get(ldapIndex).createUserContext(principal, password);
      return true;
    } catch (NamingException e) {
      LOG.debug("Password not valid for user {} in " + ldapIndex + ": {}", principal, e.getMessage());
      return false;
    } finally {
      ContextHelper.closeQuetly(context);
    }
  }

  private boolean checkPasswordUsingGssapi(String principal, String password, String ldapIndex) {
    // Use our custom configuration to avoid reliance on external config
    Configuration.setConfiguration(new Krb5LoginConfiguration());
    LoginContext lc;
    try {
      lc = new LoginContext(getClass().getName(), new CallbackHandlerImpl(principal, password));
      lc.login();
    } catch (LoginException e) {
      // Bad username: Client not found in Kerberos database
      // Bad password: Integrity check on decrypted field failed
      LOG.debug("Password not valid for {} in " + ldapIndex + ": {}", principal, e.getMessage());
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
