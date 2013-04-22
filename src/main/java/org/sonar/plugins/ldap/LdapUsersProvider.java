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

import javax.annotation.Nullable;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchResult;
import java.util.Map;

/**
 * @author Evgeny Mandrikov
 */
public class LdapUsersProvider extends ExternalUsersProvider {

  private static final Logger LOG = LoggerFactory
	  .getLogger(LdapUsersProvider.class);
  private final Map<String, LdapContextFactory> contextFactories;
  private final Map<String, LdapUserMapping> userMappings;

  public LdapUsersProvider(Map<String, LdapContextFactory> contextFactories,
	  Map<String, LdapUserMapping> userMappings) {
	this.contextFactories = contextFactories;
	this.userMappings = userMappings;
  }

  private static String getAttributeValue(@Nullable Attribute attribute)
	  throws NamingException {
	if (attribute == null) {
	  return "";
	}
	return (String) attribute.get();
  }

  /**
   * @return details for specified user, or null if such user doesn't exist
   * @throws SonarException
   *           if unable to retrieve details
   */
  public UserDetails doGetUserDetails(String username) {
	LOG.debug("Requesting details for user {}", username);
	if (userMappings.size() == 0) {
	  throw new SonarException("Unable to retrieve details for user "
		  + username);
	}
	for (String ldapIndex : userMappings.keySet()) {
	  try {
		SearchResult searchResult = userMappings
			.get(ldapIndex)
			.createSearch(contextFactories.get(ldapIndex), username)
			.returns(userMappings.get(ldapIndex).getEmailAttribute(),
				userMappings.get(ldapIndex).getRealNameAttribute())
			.findUnique();
		if (searchResult == null) {
		  // user not found
		  LOG.debug("User {} not found", username);
		  continue;
		}
		UserDetails details = new UserDetails();
		Attributes attributes = searchResult.getAttributes();
		details.setName(getAttributeValue(attributes.get(userMappings.get(
			ldapIndex).getRealNameAttribute())));
		details.setEmail(getAttributeValue(attributes.get(userMappings.get(
			ldapIndex).getEmailAttribute())));
		return details;
	  } catch (NamingException e) {
		// just in case if Sonar silently swallowed exception
		LOG.debug(e.getMessage(), e);
		throw new SonarException("Unable to retrieve details for user "
			+ username, e);
	  }
	}
	return null;
  }

}
