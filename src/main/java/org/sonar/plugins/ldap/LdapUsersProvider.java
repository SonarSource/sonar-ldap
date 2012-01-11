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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.api.security.ExternalUsersProvider;
import org.sonar.api.security.UserDetails;
import org.sonar.api.utils.SonarException;

import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchResult;

/**
 * @author Evgeny Mandrikov
 */
public class LdapUsersProvider implements ExternalUsersProvider {

  private static final Logger LOG = LoggerFactory.getLogger(LdapUsersProvider.class);

  private final LdapContextFactory contextFactory;
  private final LdapUserMapping userMapping;

  public LdapUsersProvider(LdapContextFactory contextFactory, LdapUserMapping userMapping) {
    this.contextFactory = contextFactory;
    this.userMapping = userMapping;
  }

  /**
   * @throws SonarException if unable to retrieve details
   */
  public UserDetails doGetUserDetails(String username) {
    try {
      LOG.debug("Requesting details for user {}", username);
      SearchResult searchResult = userMapping.createSearch(contextFactory, username)
          .setReturningAttributes(userMapping.getEmailAttribute(), userMapping.getRealNameAttribute())
          .findUnique();
      UserDetails details = new UserDetails();
      Attributes attributes = searchResult.getAttributes();
      details.setName(getAttributeValue(attributes.get(userMapping.getRealNameAttribute())));
      details.setEmail(getAttributeValue(attributes.get(userMapping.getEmailAttribute())));
      return details;
    } catch (NamingException e) {
      throw new SonarException("Unable to retrieve details for user " + username, e);
    }
  }

  private static String getAttributeValue(Attribute attribute) throws NamingException {
    if (attribute == null) {
      return "";
    }
    return (String) attribute.get();
  }

}
