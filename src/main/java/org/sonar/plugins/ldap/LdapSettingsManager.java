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
import org.sonar.api.config.Settings;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The LdapSettingsManager will parse the settings.
 * This class is also responsible to cope with multiple ldap servers.
 */
public class LdapSettingsManager {

  private static final Logger LOG = LoggerFactory.getLogger(LdapSettingsManager.class);

  private static final String LDAP_SERVERS_PROPERTY = "ldap.servers";
  private static final String LDAP_PROPERTY_PREFIX = "ldap";
  private static final String DEFAULT_LDAP_SERVER_KEY = "<default>";
  private final Settings settings;
  private Map<String, LdapUserMapping> userMappings = null;
  private Map<String, LdapGroupMapping> groupMappings = null;
  private Map<String, LdapContextFactory> contextFactories;

  /**
   * Create an instance of the settings manager.
   *
   * @param settings The settings to use.
   */
  public LdapSettingsManager(Settings settings) {
    this.settings = settings;
  }

  /**
   * Get all the @link{LdapUserMapping}s available in the settings.
   *
   * @return A @link{Map} with all the @link{LdapUserMapping} objects.
   *         The key is the server key used in the settings (ldap for old single server notation).
   */
  public Map<String, LdapUserMapping> getUserMappings() {
    if (userMappings == null) {
      // Use linked hash map to preserve order
      userMappings = new LinkedHashMap<String, LdapUserMapping>();
      String[] serverKeys = settings.getStringArray(LDAP_SERVERS_PROPERTY);
      if (serverKeys.length > 0) {
        for (String serverKey : serverKeys) {
          LdapUserMapping userMapping = new LdapUserMapping(settings, LDAP_PROPERTY_PREFIX + "." + serverKey);
          if (userMapping.getBaseDn() != null) {
            userMappings.put(serverKey, userMapping);
          }
        }
      } else {
        // Backward compatibility with single server configuration
        LdapUserMapping userMapping = new LdapUserMapping(settings, LDAP_PROPERTY_PREFIX);
        if (userMapping.getBaseDn() != null) {
          userMappings.put(DEFAULT_LDAP_SERVER_KEY, userMapping);
        }
      }
    }
    return userMappings;
  }

  /**
   * Get all the @link{LdapGroupMapping}s available in the settings.
   *
   * @return A @link{Map} with all the @link{LdapGroupMapping} objects.
   *         The key is the server key used in the settings (ldap for old single server notation).
   */
  public Map<String, LdapGroupMapping> getGroupMappings() {
    if (groupMappings == null) {
      // Use linked hash map to preserve order
      groupMappings = new LinkedHashMap<String, LdapGroupMapping>();
      String[] serverKeys = settings.getStringArray(LDAP_SERVERS_PROPERTY);
      if (serverKeys.length > 0) {
        for (String serverKey : serverKeys) {
          LdapGroupMapping groupMapping = new LdapGroupMapping(settings, LDAP_PROPERTY_PREFIX + "." + serverKey);
          if (StringUtils.isNotBlank(groupMapping.getBaseDn())) {
            LOG.info("Group mapping for server {}: {}", serverKey, groupMapping);
            groupMappings.put(serverKey, groupMapping);
          } else {
            LOG.info("Groups will not be synchronized for server {}, because property 'ldap.{}.group.baseDn' is empty.", serverKey, serverKey);
          }
        }
      } else {
        // Backward compatibility with single server configuration
        LdapGroupMapping groupMapping = new LdapGroupMapping(settings, LDAP_PROPERTY_PREFIX);
        if (StringUtils.isNotBlank(groupMapping.getBaseDn())) {
          LOG.info("Group mapping: {}", groupMapping);
          groupMappings.put(DEFAULT_LDAP_SERVER_KEY, groupMapping);
        } else {
          LOG.info("Groups will not be synchronized, because property 'ldap.group.baseDn' is empty.");
        }
      }
    }
    return groupMappings;
  }

  /**
   * Get all the @link{LdapContextFactory}s available in the settings.
   *
   * @return A @link{Map} with all the @link{LdapContextFactory} objects.
   *        The key is the server key used in the settings (ldap for old single server notation).
   */
  public Map<String, LdapContextFactory> getContextFactories() {
    if (contextFactories == null) {
      // Use linked hash map to preserve order
      contextFactories = new LinkedHashMap<String, LdapContextFactory>();
      String[] serverKeys = settings.getStringArray(LDAP_SERVERS_PROPERTY);
      if (serverKeys.length > 0) {
        for (String serverKey : serverKeys) {
          LdapContextFactory contextFactory = new LdapContextFactory(settings, LDAP_PROPERTY_PREFIX + "." + serverKey);
          if (StringUtils.isNotBlank(contextFactory.getProviderUrl())) {
            contextFactories.put(serverKey, contextFactory);
          }
        }
      } else {
        // Backward compatibility with single server configuration
        LdapContextFactory contextFactory = new LdapContextFactory(settings, LDAP_PROPERTY_PREFIX);
        if (StringUtils.isNotBlank(contextFactory.getProviderUrl())) {
          contextFactories.put(DEFAULT_LDAP_SERVER_KEY, contextFactory);
        }
      }
    }
    return contextFactories;
  }
}
