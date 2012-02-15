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

/**
 * Helper methods for construction of {@link LdapContextFactory}.
 */
public final class LdapContextFactories {

  private LdapContextFactories() {
  }

  public static LdapContextFactory createForAnonymousAccess(String ldapUrl) {
    Settings settings = new Settings();
    settings.setProperty("ldap.url", ldapUrl);
    return new LdapContextFactory(settings);
  }

  public static LdapContextFactory createForSimpleBind(String ldapUrl, String username, String password) {
    Settings settings = new Settings();
    settings.setProperty("ldap.url", ldapUrl);
    settings.setProperty("ldap.bindDn", username);
    settings.setProperty("ldap.bindPassword", password);
    return new LdapContextFactory(settings);
  }

  public static LdapContextFactory createForAuthenticationMethod(String ldapUrl, String authentication, String realm, String username, String password) {
    Settings settings = new Settings();
    settings.setProperty("ldap.url", ldapUrl);
    settings.setProperty("ldap.bindDn", username);
    settings.setProperty("ldap.bindPassword", password);
    settings.setProperty("ldap.authentication", authentication);
    settings.setProperty("ldap.realm", realm);
    return new LdapContextFactory(settings);
  }

}
