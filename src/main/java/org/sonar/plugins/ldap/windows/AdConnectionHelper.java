/*
 * SonarQube LDAP Plugin
 * Copyright (C) 2009 SonarSource
 * sonarqube@googlegroups.com
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
package org.sonar.plugins.ldap.windows;

import com.google.common.base.Preconditions;
import com4j.ComException;
import com4j.typelibs.activeDirectory.IADs;
import com4j.typelibs.ado20.Field;
import com4j.typelibs.ado20.Fields;
import com4j.typelibs.ado20._Command;
import com4j.typelibs.ado20._Connection;
import com4j.typelibs.ado20._Recordset;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.plugins.ldap.windows.auth.ICom4jWrapper;
import org.sonar.plugins.ldap.windows.auth.impl.Com4jWrapper;

public class AdConnectionHelper {
  private static final Logger LOG = LoggerFactory.getLogger(AdConnectionHelper.class);

  /**
   * Active directory service object provider
   */
  public static final String ADS_OBJECT_PROVIDER_STR = "ADsDSOObject";

  /**
   * Root of the directory data tree on a diretory server
   */
  public static final String ROOT_DSE = "RootDSE";

  /**
   * Attribute for storing distinguished name for the domain of which a particular directory server is member-of.
   */
  public static final String DEFAULT_NAMING_CONTEXT_STR = "defaultNamingContext";

  /**
   * Default active directory connection string
   */
  public static final String DEFAULT_AD_CONNECTION_STR = "Active Directory Provider";

  /**
   * Attribute for storing logon name of a user in an active directory
   */
  public static final String SAMACCOUNTNAME_STR = "sAMAccountName";

  /**
   * Attribute for storing common name of a user in an active directory
   */
  public static final String COMMON_NAME_ATTRIBUTE = "cn";

  /**
   * Attribute for storing email of a user in an active directory
   */
  public static final String MAIL_ATTRIBUTE = "mail";

  private final ICom4jWrapper com4jWrapper;

  public AdConnectionHelper() {
    this(new Com4jWrapper());
  }

  AdConnectionHelper(ICom4jWrapper com4jWrapper) {
    this.com4jWrapper = com4jWrapper;
  }

  /**
   * Retrieves the requested details from an active directory for the given user
   *
   * @param domainName       Domain name
   * @param userName         User name
   * @param requestedDetails {@link Collection} of {@link String}
   * @return {@link Map} of requested user details.
   */
  public Map<String, String> getUserDetails(final String domainName, final String userName,
    final Collection<String> requestedDetails) {
    Preconditions.checkArgument(domainName != null && !domainName.isEmpty(), "domainName is null or empty");
    Preconditions.checkArgument(userName != null && !userName.isEmpty(), "userName is null or empty");
    Preconditions.checkArgument(requestedDetails != null && !requestedDetails.isEmpty(),
      "requestedDetails is null or empty");

    Map<String, String> userDetails = new HashMap<>();
    _Connection connection = null;
    _Recordset recordSet = null;
    try {
      String defaultNamingContext = getDefaultNamingContext(domainName);
      if (defaultNamingContext == null) {
        return userDetails;
      }

      connection = getActiveDirectoryConnection();
      if (connection == null) {
        return userDetails;
      }

      String commandText = getCommandText(defaultNamingContext, userName, requestedDetails);
      LOG.trace(commandText);

      recordSet = executeCommand(connection, commandText);
      if (recordSet != null) {
        Map<String, String> adUserDetails = getUserDetailsFromRecordSet(recordSet, userName, domainName,
          requestedDetails);
        if (adUserDetails != null) {
          userDetails.putAll(adUserDetails);
        }
      }
    } finally {
      if (recordSet != null) {
        recordSet.close();
        recordSet.dispose();
      }
      if (connection != null) {
        connection.close();
        connection.dispose();
      }
      com4jWrapper.cleanUp();
    }

    return userDetails;
  }

  /**
   * Returns the default naming context of the active directory for given domain
   *
   * @return {@link String} Default naming context.
   */
  String getDefaultNamingContext(String domainName) {
    String defaultNamingContext = null;
    IADs rootDse = null;
    try {
      rootDse = com4jWrapper.getObject(IADs.class, String.format("GC://%s/%s", domainName, ROOT_DSE), null);
      defaultNamingContext = (String) rootDse.get(DEFAULT_NAMING_CONTEXT_STR);
    } catch (ComException comException) {
      LOG.debug("Unable to get {} for domain: {}: {}", DEFAULT_NAMING_CONTEXT_STR, domainName,
        comException.getMessage());
    }

    return defaultNamingContext;
  }

  /**
   * Returns the active directory _Connection object
   *
   * @return {@link _Connection}
   */
  _Connection getActiveDirectoryConnection() {
    _Connection connection = com4jWrapper.createConnection();
    if (connection != null) {
      connection.provider(ADS_OBJECT_PROVIDER_STR);
      try {
        connection.open(DEFAULT_AD_CONNECTION_STR, "", "", -1);
      } catch (ComException comException) {
        LOG.error("Unable to get connection to active directory. {}", comException.getMessage());
        connection = null;
      }
    } else {
      LOG.error("Unable to create connection to active directory.");
    }

    return connection;
  }

  /**
   * Returns the attribute value from given Fields
   *
   * @return {@link String} attributes value or null if the attribute is not found
   */
  String getUserAttributeValue(final Fields userData, final String attributeName) {
    String attributeValue = null;
    try {
      Field field = userData.item(attributeName);
      if (field != null) {
        Object obj = field.value();
        if (obj != null) {
          attributeValue = obj.toString();
        }
      }
    } catch (ComException comException) {
      LOG.debug("Unable to get {}. {}", attributeName, comException.getMessage());
    }

    return attributeValue;
  }

  private _Recordset executeCommand(final _Connection connection, final String commandText) {
    _Recordset recordSet = null;
    _Command command = null;
    try {
      command = com4jWrapper.createCommand();
      if (command != null) {
        command.activeConnection(connection);
        command.commandText(commandText);
        recordSet = command.execute(null, com4jWrapper.getMissing(), -1);
      } else {
        LOG.error("Unable to create the active directory command");
      }
    } finally {
      if (command != null) {
        command.dispose();
      }
    }

    return recordSet;
  }

  private Map<String, String> getUserDetailsFromRecordSet(final _Recordset recordSet, final String userName,
    final String domainName, final Collection<String> requestedDetails) {
    Map<String, String> userDetails = new HashMap<>();

    if (recordSet.eof()) {
      LOG.debug(userName + " not found in the domain " + domainName);
      return null;
    } else {
      Fields userData = recordSet.fields();
      if (userData != null) {
        for (String requestedDetail : requestedDetails) {
          userDetails.put(requestedDetail, getUserAttributeValue(userData, requestedDetail));
        }
      }
    }

    return userDetails;
  }

  /*
   * Command Text format <GC://root>;(filter);requestedAttributes;scope
   * e.g.<GC://DC=domain, dc=com>;(sAMAccountName=userName);ch,mail;SubTree
   */
  private static String getCommandText(final String namingContext, final String userName,
    final Collection<String> requestedDetails) {
    /* Specify the command to search a global catalog server using GC moniker */
    String root = String.format("<GC://%s>", namingContext);
    /* Filter on sAMAccountName attribute */
    String filter = String.format("(%s=%s)", SAMACCOUNTNAME_STR, userName);
    /* Requested user attributes */
    String requestedAttributes = StringUtils.join(requestedDetails, ",");
    /* Search scope as SubTree */
    String scope = "SubTree";

    return String.format("%s;%s;%s;%s", root, filter, requestedAttributes, scope);
  }

}
