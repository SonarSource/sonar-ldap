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

import java.util.HashMap;
import java.util.Map;

/**
 * Created with IntelliJ IDEA.
 * User: Robby
 * Date: 17/04/13
 * Time: 11:50
 * To change this template use File | Settings | File Templates.
 */
public class LdapSettingsManager {
    public static final String LDAP = "ldap";
    Settings settings;
    private Map<String,LdapUserMapping> userMappings = null;
    private Map<String, LdapGroupMapping> groupMappings = null;
    private Map<String, LdapContextFactory> contextFactories;

    public LdapSettingsManager(Settings settings) {
        this.settings = settings;
    }

    public Map<String, LdapUserMapping> getUserMappings(){
        if(userMappings == null){
        userMappings = new HashMap<String, LdapUserMapping>();
        int index = 1;
        String ldapIndex = LDAP;
        while(settings.getString(ldapIndex + ".user.baseDn")!=null){
                userMappings.put(ldapIndex, new LdapUserMapping(settings, ldapIndex));
            ldapIndex = LDAP + index;
            index++;
        }
        }
        return userMappings;
    }

    public Map<String,LdapGroupMapping> getGroupMappings() {
        if(groupMappings == null){
            groupMappings = new HashMap<String, LdapGroupMapping>();
            int index = 1;
            String ldapIndex = LDAP;
            while(settings.getString(ldapIndex + ".group.baseDn")!=null){
               groupMappings.put(ldapIndex, new LdapGroupMapping(settings,ldapIndex));
               ldapIndex = LDAP + index;
                index++;
            }
        }
        return groupMappings;
    }

    public Map<String, LdapContextFactory> getContextFactories() {
        if(contextFactories == null){
            contextFactories = new HashMap<String, LdapContextFactory>();
            int index = 1;
            String ldapIndex = LDAP;
            while(settings.getString(ldapIndex + ".url")!=null){
                contextFactories.put(ldapIndex, new LdapContextFactory(settings,ldapIndex));
                ldapIndex = LDAP + index;
                index++;
            }
        }
        return contextFactories;
    }
}
