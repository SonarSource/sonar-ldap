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

import com.google.common.annotations.VisibleForTesting;
import com4j.ComException;
import com4j.ExecutionException;
import com4j.typelibs.activeDirectory.IADs;
import com4j.typelibs.ado20.Field;
import com4j.typelibs.ado20.Fields;
import com4j.typelibs.ado20._Command;
import com4j.typelibs.ado20._Connection;
import com4j.typelibs.ado20._Recordset;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import org.apache.commons.lang.StringUtils;
import org.sonar.api.utils.log.Logger;
import org.sonar.api.utils.log.Loggers;
import org.sonar.plugins.ldap.windows.auth.ICom4jWrapper;
import org.sonar.plugins.ldap.windows.auth.impl.Com4jWrapper;

import static com.google.common.base.Preconditions.checkArgument;
import static org.apache.commons.lang.StringUtils.isNotEmpty;

public class AdConnectionHelper {
  private static final Logger LOG = Loggers.get(AdConnectionHelper.class);

  /**
   * Active directory service object provider
   */
  public static final String ADS_OBJECT_PROVIDER_STR = "ADsDSOObject";

  /**
   * Root of the directory data tree on a directory server
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
   * Attribute for storing distinguished name of a user
   * E.g. User Name,OU=Users,DC=domain,DC=com
   */
  public static final String DISTINGUISHED_NAME_STR = "distinguishedName";

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
    checkArgument(isNotEmpty(domainName), "domainName is null or empty");
    checkArgument(isNotEmpty(userName), "userName is null or empty");
    checkArgument(requestedDetails != null && !requestedDetails.isEmpty(),
      "requestedDetails is null or empty");

    Map<String, String> userDetails = new HashMap<>();
    _Connection connection = null;
    try {
      String activeDirectoryBindString = getActiveDirectoryBindString(domainName);
      if (activeDirectoryBindString == null) {
        return userDetails;
      }

      connection = getActiveDirectoryConnection();
      if (connection == null) {
        return userDetails;
      }

      userDetails = getUserDetailsFromAd(connection, activeDirectoryBindString, domainName, userName, requestedDetails);
    } finally {
      if (connection != null) {
        connection.close();
        connection.dispose();
      }
      com4jWrapper.cleanUp();
    }

    return userDetails;
  }

  public Collection<String> getUserGroupsInDomain(final String domainName, final String userName,
    final String requestedGroupIdAttribute) {
    checkArgument(isNotEmpty(domainName), "domainName is null or empty");
    checkArgument(isNotEmpty(userName), "userName is null or empty");
    checkArgument(isNotEmpty(requestedGroupIdAttribute), "requestedGroupIdAttribute is null or empty");

    Collection<String> userGroups = new ArrayList<>();

    _Connection connection = null;
    try {
      String activeDirectoryBindString = getActiveDirectoryBindString(domainName);
      if (activeDirectoryBindString == null) {
        return userGroups;
      }

      connection = getActiveDirectoryConnection();
      if (connection == null) {
        return userGroups;
      }

      String userNameDn = getUserDistinguishedName(connection, activeDirectoryBindString, domainName, userName);
      if (StringUtils.isBlank(userNameDn)) {
        return userGroups;
      }

      Collection<String> adUserGroups = getUserGroupsFromAd(connection, activeDirectoryBindString, userNameDn,
        requestedGroupIdAttribute);
      userGroups.addAll(adUserGroups);

    } finally {
      if (connection != null) {
        connection.close();
        connection.dispose();
      }
      com4jWrapper.cleanUp();
    }

    return userGroups;
  }

  /**
   * Returns the bind string of one of the available active directory controllers in the given domain.
   */
  @VisibleForTesting
  String getActiveDirectoryBindString(String domainName) {
    String connectionUrl = null;

    LOG.debug("Getting active directory bind string for domain: {}", domainName);
    IADs rootDse = null;
    try {
      rootDse = getRootDse(domainName);
      if (rootDse != null) {
        String defaultNamingContext = (String) getRootDseAttribute(rootDse, DEFAULT_NAMING_CONTEXT_STR);
        if (StringUtils.isNotBlank(defaultNamingContext)) {
          connectionUrl = String.format("LDAP://%s/%s", domainName, defaultNamingContext);
        }
      }
    } finally {
      if (rootDse != null) {
        rootDse.dispose();
      }
    }

    if (StringUtils.isNotBlank(connectionUrl)) {
      LOG.debug("Active directory bind string for the domain {}: {}", domainName, connectionUrl);
    } else {
      LOG.debug("Unable to get the active directory bind string for the domain {}", domainName);
    }

    return connectionUrl;
  }

  /**
   * Returns the active directory _Connection object
   *
   * @return {@link _Connection}
   */
  @VisibleForTesting
  _Connection getActiveDirectoryConnection() {
    _Connection connection = com4jWrapper.createConnection();
    if (connection != null) {
      connection.provider(ADS_OBJECT_PROVIDER_STR);
      try {
        connection.open(DEFAULT_AD_CONNECTION_STR, "", "", -1);
      } catch (ComException | ExecutionException ex) {
        LOG.error("Unable to get connection to the active directory. {}", ex.getMessage());
        connection = null;
      }
    } else {
      LOG.error("Unable to create connection to the active directory.");
    }

    return connection;
  }

  /**
   * Returns the attribute value from given Fields
   *
   * @return {@link String} attributes value or null if the attribute is not found
   */
  @VisibleForTesting
  String getUserAttributeValue(final Fields userData, final String attributeName) {
    String attributeValue = null;
    try {
      Field field = userData.item(attributeName);
      if (field != null) {
        Object obj = field.value();
        if (obj != null) {
          attributeValue = obj.toString();
          LOG.trace("Value of user attribute {}: {}", attributeName, attributeValue);
        }
      } else {
        LOG.debug("User attribute {} doesn't exist.", attributeName);
      }
    } catch (ComException comException) {
      LOG.debug("Unable to get {}. {}", attributeName, comException.getMessage());
    }

    return attributeValue;
  }

  private static Object getRootDseAttribute(IADs rootDse, String attributeName) {
    Object attributeValue = null;
    try {
      LOG.trace("Getting value of {} from {}", attributeName, ROOT_DSE);
      attributeValue = rootDse.get(attributeName);
      LOG.trace("Value of {} from {} : {}", attributeName, ROOT_DSE, attributeValue);
    } catch (ComException comException) {
      LOG.debug("Unable to get value of attribute {} from {}: {}", attributeName, ROOT_DSE, comException.getMessage());
    }

    return attributeValue;
  }

  private IADs getRootDse(String domainName) {
    IADs rootDse = null;

    String adBindString = String.format("LDAP://%s/%s", domainName, ROOT_DSE);
    try {
      rootDse = com4jWrapper.getObject(IADs.class, adBindString, null);
    } catch (ComException | ExecutionException ex) {
      // ExecutionException will be thrown if the server is unavailable
      LOG.debug("Unable to get {} for the active directory bind string {}: {}", ROOT_DSE, adBindString, ex.getMessage());
    }

    return rootDse;
  }

  private Map<String, String> getUserDetailsFromAd(final _Connection connection, final String connectionUrl, String domainName,
    String userName, final Collection<String> requestedDetails) {
    Map<String, String> userDetails = new HashMap<>();

    String commandText = getUserDetailsCommandText(connectionUrl, userName, requestedDetails);

    Collection<Map<String, String>> userDetailsRecords = executeQuery(connection, commandText, requestedDetails);

    if (userDetailsRecords.size() == 1) {
      userDetails = userDetailsRecords.iterator().next();
    } else {
      LOG.debug("No details record for the user found: " + domainName + "\\" + userName);
    }

    return userDetails;
  }

  private String getUserDistinguishedName(final _Connection connection, final String connectionUrl, final String domainName,
    final String userName) {
    Collection<String> requestedUserAttributes = new ArrayList<>();
    requestedUserAttributes.add(DISTINGUISHED_NAME_STR);

    Map<String, String> userAttributes = getUserDetailsFromAd(connection, connectionUrl, domainName, userName, requestedUserAttributes);

    return userAttributes.get(DISTINGUISHED_NAME_STR);
  }

  private Collection<String> getUserGroupsFromAd(final _Connection connection, final String connectionUrl,
    final String userNameDn, final String requestedGroupIdAttribute) {
    Collection<String> adUserGroups = new ArrayList<>();

    String commandText = getUserGroupsCommandText(connectionUrl, userNameDn, requestedGroupIdAttribute);
    Collection<String> requestedAttributes = new ArrayList<>();
    requestedAttributes.add(requestedGroupIdAttribute);

    Collection<Map<String, String>> groupRecords = executeQuery(connection, commandText, requestedAttributes);
    for (Map<String, String> groupRecord : groupRecords) {
      String groupIdValue = groupRecord.get(requestedGroupIdAttribute);
      if (StringUtils.isNotBlank(groupIdValue))
        adUserGroups.add(groupIdValue);
    }

    return adUserGroups;
  }

  private Collection<Map<String, String>> executeQuery(final _Connection connection, String commandText,
    final Collection<String> requestedDetails) {
    Collection<Map<String, String>> records = new ArrayList<>();

    _Recordset recordSet = null;
    try {
      recordSet = executeCommand(connection, commandText);
      if (recordSet != null) {
        records = getDataFromRecordSet(recordSet, requestedDetails);
      }
    } finally {
      if (recordSet != null) {
        recordSet.close();
        recordSet.dispose();
      }
    }

    return records;
  }

  private Collection<Map<String, String>> getDataFromRecordSet(final _Recordset recordSet, final Collection<String> requestedDetails) {
    Collection<Map<String, String>> records = new ArrayList<>();

    try {
      while (!recordSet.eof()) {
        Fields userData = recordSet.fields();
        if (userData != null) {
          Map<String, String> requestedDetailsMap = new HashMap<>();
          for (String requestedDetail : requestedDetails) {
            String userAttributeValue = getUserAttributeValue(userData, requestedDetail);
            requestedDetailsMap.put(requestedDetail, userAttributeValue);
          }
          records.add(requestedDetailsMap);
        }
        recordSet.moveNext();
      }
    } catch (ComException comException) {
      LOG.debug("Exception while getting data from the record-set :  {} ", comException.getMessage());
    }

    return records;
  }

  private _Recordset executeCommand(final _Connection connection, final String commandText) {
    _Recordset recordSet = null;
    _Command command = null;
    try {
      command = com4jWrapper.createCommand(connection, commandText);
      if (command != null) {
        LOG.trace("Executing command: {}", commandText);
        recordSet = command.execute(null, com4jWrapper.getMissing(), -1);
      } else {
        LOG.error("Unable to create the active directory command {}", commandText);
      }
    } catch (ComException comException) {
      LOG.debug("Exception while executing the command :  {} ", comException.getMessage());
    } finally {
      if (command != null) {
        command.dispose();
      }
    }

    return recordSet;
  }

  /*
   * User Details Command Text format <LDAP://domain/root>;(filter);requestedAttributes;scope
   * e.g.<LDAP://domain/DC=domain, dc=com>;(sAMAccountName=userName);cn,mail;SubTree
   */
  private static String getUserDetailsCommandText(final String bindString, final String userName,
    final Collection<String> requestedDetails) {
    /* Filter on sAMAccountName attribute */
    String filter = String.format("(%s=%s)", SAMACCOUNTNAME_STR, userName);
    /* Requested user attributes */
    String requestedAttributes = StringUtils.join(requestedDetails, ",");

    return String.format("<%s>;%s;%s;SubTree", bindString, filter, requestedAttributes);
  }

  /*
   * User Groups Command Text format <LDAP://domain/root>;(filter);requestedAttributes;scope
   */
  private static String getUserGroupsCommandText(final String bindString, final String userDn,
    final String requestedDetail) {
    /* Filter on user dn attribute */
    String filter = String.format("(&(objectClass=group)(member=%s))", userDn);

    return String.format("<%s>;%s;%s;SubTree", bindString, filter, requestedDetail);
  }
}
