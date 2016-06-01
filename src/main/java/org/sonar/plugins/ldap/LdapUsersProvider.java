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
package org.sonar.plugins.ldap;

import java.util.Map;
import javax.annotation.Nullable;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchResult;
import org.sonar.api.security.ExternalUsersProvider;
import org.sonar.api.security.UserDetails;
import org.sonar.api.utils.SonarException;
import org.sonar.api.utils.log.Logger;
import org.sonar.api.utils.log.Loggers;

import static java.lang.String.format;

/**
 * @author Evgeny Mandrikov
 */
public class LdapUsersProvider extends ExternalUsersProvider {

  private static final Logger LOG = Loggers.get(LdapUsersProvider.class);
  private final Map<String, LdapContextFactory> contextFactories;
  private final Map<String, LdapUserMapping> userMappings;

  public LdapUsersProvider(Map<String, LdapContextFactory> contextFactories, Map<String, LdapUserMapping> userMappings) {
    this.contextFactories = contextFactories;
    this.userMappings = userMappings;
  }

  private static String getAttributeValue(@Nullable Attribute attribute) throws NamingException {
    if (attribute == null) {
      return "";
    }
    return (String) attribute.get();
  }

  /**
   * @return details for specified user, or null if such user doesn't exist
   * @throws SonarException if unable to retrieve details
   */
  @Override
  public UserDetails doGetUserDetails(Context context) {
    String username = context.getUsername();
    LOG.debug("Requesting details for user {}", username);
    // If there are no userMappings available, we can not retrieve user details.
    if (userMappings.isEmpty()) {
      String errorMessage = format("Unable to retrieve details for user %s: No user mapping found.", username);
      LOG.debug(errorMessage);
      throw new SonarException(errorMessage);
    }
    UserDetails details = null;
    SonarException sonarException = null;
    for (Map.Entry<String, LdapUserMapping> userMappingEntry : userMappings.entrySet()) {
      String serverKey = userMappingEntry.getKey();
      LdapUserMapping userMapping = userMappingEntry.getValue();
      SearchResult searchResult = null;
      try {
        searchResult = userMapping.createSearch(contextFactories.get(serverKey), username)
          .returns(userMapping.getEmailAttribute(), userMapping.getRealNameAttribute())
          .findUnique();
      } catch (NamingException e) {
        // just in case if Sonar silently swallowed exception
        LOG.debug(e.getMessage(), e);
        sonarException = new SonarException("Unable to retrieve details for user " + username + " in " + serverKey, e);
      }
      if (searchResult != null) {
        try {
          details = mapUserDetails(userMapping, searchResult);
          // if no exceptions occur, we found the user and mapped his details.
          break;
        } catch (NamingException e) {
          // just in case if Sonar silently swallowed exception
          LOG.debug(e.getMessage(), e);
          sonarException = new SonarException("Unable to retrieve details for user " + username + " in " + serverKey, e);
        }
      } else {
        // user not found
        LOG.debug("User {} not found in {}", username, serverKey);
        continue;
      }
    }
    if (details == null && sonarException != null) {
      // No user found and there is an exception so there is a reason the user could not be found.
      throw sonarException;
    }
    return details;
  }

  /**
   * Map the properties from LDAP to the {@link UserDetails}
   *
   * @param userMapping {@link LdapUserMapping}
   * @return If no exceptions are thrown, a {@link UserDetails} object containing the values from LDAP.
   * @throws NamingException In case the communication or mapping to the LDAP server fails.
   */
  private static UserDetails mapUserDetails(LdapUserMapping userMapping, SearchResult searchResult) throws NamingException {
    Attributes attributes = searchResult.getAttributes();
    UserDetails details = new UserDetails();
    details.setName(getAttributeValue(attributes.get(userMapping.getRealNameAttribute())));
    details.setEmail(getAttributeValue(attributes.get(userMapping.getEmailAttribute())));

    return details;
  }

}
