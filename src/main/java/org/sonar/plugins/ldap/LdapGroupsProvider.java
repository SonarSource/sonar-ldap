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

import java.util.Collection;
import java.util.HashSet;
import java.util.Map;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchResult;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.api.security.ExternalGroupsProvider;
import org.sonar.api.utils.SonarException;

import com.google.common.collect.Sets;

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
	 *             if unable to retrieve groups
	 */
	public Collection<String> doGetGroups(String username) {
		if (userMappings.keySet().size() == 0
				|| groupMappings.keySet().size() == 0) {
			String errorMessage = "Unable to retrieve details for user "
					+ username + ": No user or group mapping found.";
			LOG.debug(errorMessage);
			throw new SonarException(errorMessage);
		}
		HashSet<String> groups = Sets.newHashSet();
		SonarException sonarException = null;
		for (String ldapIndex : userMappings.keySet()) {
			if (!groupMappings.containsKey(ldapIndex)) {
				// No group mapping for this ldap instance.
				continue;
			}
			SearchResult searchResult = null;
			try {
				LOG.debug("Requesting groups for user {}", username);

				searchResult = userMappings
						.get(ldapIndex)
						.createSearch(contextFactories.get(ldapIndex), username)
						.returns(
								groupMappings.get(ldapIndex)
										.getRequiredUserAttributes())
						.findUnique();
			} catch (NamingException e) {
				// just in case if Sonar silently swallowed exception
				LOG.debug(e.getMessage(), e);
				sonarException = new SonarException(
						"Unable to retrieve groups for user " + username
								+ " in " + ldapIndex, e);
			}
			if (searchResult != null) {
				try {
					NamingEnumeration<SearchResult> result = groupMappings
							.get(ldapIndex)
							.createSearch(contextFactories.get(ldapIndex),
									searchResult).find();
					groups.addAll(mapGroups(ldapIndex, result));
					// TODO: check if we want to continue, the user can be part
					// of groups in multiple domains.
					// if no exceptions occur, we found the user and his groups
					// and mapped his details.
					break;
				} catch (NamingException e) {
					// just in case if Sonar silently swallowed exception
					LOG.debug(e.getMessage(), e);
					sonarException = new SonarException(
							"Unable to retrieve groups for user " + username
									+ " in " + ldapIndex, e);
				}
			} else {
				// user not found
				continue;
			}
		}
		if (groups.isEmpty() && sonarException != null) {
			// No groups found and there is an exception so there is a reason
			// the user could not be found.
			throw sonarException;
		}
		return groups;
	}

	/**
	 * Map all the groups.
	 * 
	 * @param ldapIndex
	 *            The index we use to choose the correct
	 *            {@link LdapGroupMapping}.
	 * @param searcResult
	 *            The {@link SearchResult} from the search for the user.
	 * @return A {@link Collection} of groups the user is member of.
	 * @throws NamingException
	 */
	private Collection<? extends String> mapGroups(String ldapIndex,
			NamingEnumeration<SearchResult> searcResult) throws NamingException {
		HashSet<String> groups = new HashSet<String>();
		while (searcResult.hasMoreElements()) {
			SearchResult obj = (SearchResult) searcResult.nextElement();
			Attributes attributes = obj.getAttributes();
			String groupId = (String) attributes.get(
					groupMappings.get(ldapIndex).getIdAttribute()).get();
			groups.add(groupId);
		}
		return groups;
	}

}
