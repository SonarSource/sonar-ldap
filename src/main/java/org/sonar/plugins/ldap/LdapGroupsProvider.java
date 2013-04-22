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

import com.google.common.collect.Sets;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.api.security.ExternalGroupsProvider;
import org.sonar.api.utils.SonarException;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchResult;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;

/**
 * @author Evgeny Mandrikov
 */
public class LdapGroupsProvider extends ExternalGroupsProvider {

  private static final Logger LOG = LoggerFactory
	  .getLogger(LdapGroupsProvider.class);

  private final Map<String, LdapContextFactory> contextFactories;
  private final Map<String, LdapUserMapping> userMappings;
  private final Map<String, LdapGroupMapping> groupMappings;

  public LdapGroupsProvider(Map<String, LdapContextFactory> contextFactories,
	  Map<String, LdapUserMapping> userMappings,
	  Map<String, LdapGroupMapping> groupMapping) {
	this.contextFactories = contextFactories;
	this.userMappings = userMappings;
	this.groupMappings = groupMapping;
  }

  /**
   * @throws SonarException
   *           if unable to retrieve groups
   */
  public Collection<String> doGetGroups(String username) {
	if (userMappings.keySet().size() == 0 || groupMappings.keySet().size() == 0) {
	  throw new SonarException("Unable to retrieve groups for user " + username);
	}
	for (String ldapIndex : userMappings.keySet()) {
	  if (!groupMappings.containsKey(ldapIndex)) {
		// No group mapping for this ldap instance.
		continue;
	  }
	  try {
		LOG.debug("Requesting groups for user {}", username);

		SearchResult searchResult = userMappings.get(ldapIndex)
			.createSearch(contextFactories.get(ldapIndex), username)
			.returns(groupMappings.get(ldapIndex).getRequiredUserAttributes())
			.findUnique();
		if (searchResult == null) {
		  // user not found
		  continue;
		}

		NamingEnumeration result = groupMappings.get(ldapIndex)
			.createSearch(contextFactories.get(ldapIndex), searchResult).find();
		HashSet<String> groups = Sets.newHashSet();
		while (result.hasMoreElements()) {
		  SearchResult obj = (SearchResult) result.nextElement();
		  Attributes attributes = obj.getAttributes();
		  String groupId = (String) attributes.get(
			  groupMappings.get(ldapIndex).getIdAttribute()).get();
		  groups.add(groupId);
		}
		return groups;
	  } catch (NamingException e) {
		// just in case if Sonar silently swallowed exception
		LOG.debug(e.getMessage(), e);
		throw new SonarException("Unable to retrieve groups for user "
			+ username, e);
	  }
	}
	return Collections.emptyList();
  }

}
