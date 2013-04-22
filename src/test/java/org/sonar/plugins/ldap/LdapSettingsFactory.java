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

import org.sonar.api.config.Settings;
import org.sonar.plugins.ldap.server.LdapServer;

/**
 * Create Settings for most used test cases.
 */
public class LdapSettingsFactory {

	public static final String LDAP = "ldap";

	/**
	 * Generate simple settings for 2 ldap servers that allows anonymous access.
	 * 
	 * @return The specific settings.
	 */
	public static Settings generateSimpleAnonymousAccessSettings(
			LdapServer exampleServer, LdapServer infosupportServer) {
		Settings settings = new Settings();

		settings.setProperty("ldap.url", exampleServer.getUrl())
				.setProperty("ldap.user.baseDn", "ou=users,dc=example,dc=org")
				.setProperty("ldap.group.baseDn", "ou=groups,dc=example,dc=org");
		if (infosupportServer != null) {
			settings.setProperty("ldap1.url", infosupportServer.getUrl())
					.setProperty("ldap1.user.baseDn",
							"ou=users,dc=infosupport,dc=com")
					.setProperty("ldap1.group.baseDn",
							"ou=groups,dc=infosupport,dc=com");
		}
		return settings;
	}

	/**
	 * Generate settings for 2 ldap servers that require authenticaten.
	 * 
	 * @param exampleServer
	 *            The first ldap server.
	 * @param infosupportServer
	 *            The second ldap server.
	 * @return The specific settings.
	 */
	public static Settings generateAuthenticationSettings(
			LdapServer exampleServer, LdapServer infosupportServer) {
		Settings settings = new Settings();
		settings.setProperty("ldap.url", exampleServer.getUrl())
				.setProperty("ldap.bindDn", "bind")
				.setProperty("ldap.bindPassword", "bindpassword")
				.setProperty("ldap.authentication",
						LdapContextFactory.CRAM_MD5_METHOD)
				.setProperty("ldap.realm", "example.org")
				.setProperty("ldap.user.baseDn", "ou=users,dc=example,dc=org")
				.setProperty("ldap.group.baseDn", "ou=groups,dc=example,dc=org");
		if (infosupportServer != null) {
			settings.setProperty("ldap1.url", infosupportServer.getUrl())
					.setProperty("ldap1.bindDn", "bind")
					.setProperty("ldap1.bindPassword", "bindpassword")
					.setProperty("ldap1.authentication",
							LdapContextFactory.CRAM_MD5_METHOD)
					.setProperty("ldap1.realm", "infosupport.com")
					.setProperty("ldap1.user.baseDn",
							"ou=users,dc=infosupport,dc=com")
					.setProperty("ldap1.group.baseDn",
							"ou=groups,dc=infosupport,dc=com");
		}
		return settings;
	}
}
