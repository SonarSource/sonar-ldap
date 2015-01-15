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

public class Main
{
    static
    {
        System.setProperty(org.slf4j.impl.SimpleLogger.DEFAULT_LOG_LEVEL_KEY, "TRACE");
    }
    public static void main(String[] args)
    {

        LdapSettingsManager settingsManager = new LdapSettingsManager(generateAuthenticationSettings(), null);
        LdapAuthenticator ldapAuthenticator = new LdapAuthenticator(settingsManager.getContextFactories(), settingsManager.getUserMappings());
        ldapAuthenticator.init();
        boolean authenticate = ldapAuthenticator.authenticate("Roettges.Florian@ads.local", "2383ThisIsSecure2383");
        System.out.println(authenticate);
        System.out.println(authenticate);
    }

    private static Settings generateAuthenticationSettings()
    {
        Settings settings = new Settings();

        settings.setProperty("ldap.url", "ldap://iiv-ticket.ads.local/dc=ldap,dc=proxy")
                .setProperty("ldap.bindDn", "cn=bind,ou=svn,dc=ldap,dc=proxy")
                .setProperty("ldap.bindPassword", "ldapproxysvn")
                //.setProperty("ldap.authentication", LdapContextFactory.CRAM_MD5_METHOD)
                .setProperty("ldap.user.request","(&(objectClass=user)(userPrincipalName={login}))")
                .setProperty("ldap.user.baseDn", "ou=svn")
                .setProperty("ldap.user.findMode",SingleEntryFindMode.FIND_FIRST.toString())
                .setProperty("ldap.referralHandling",LdapReferralHandling.DENY_ALL.toString());
        return settings;
    }
}
