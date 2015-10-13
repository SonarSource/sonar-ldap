/*
 * SonarQube LDAP Plugin
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

import com.google.common.base.Objects;
import com.sun.jna.platform.win32.Advapi32Util;
import com.sun.jna.platform.win32.WinNT.PSID;

import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.SearchResult;
import org.apache.commons.lang.StringUtils;
import org.slf4j.LoggerFactory;
import org.sonar.api.config.Settings;
import org.sonar.api.utils.SonarException;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * @author Evgeny Mandrikov
 */
public class LdapGroupMapping {

  private static final String DEFAULT_OBJECT_CLASS = "groupOfUniqueNames";
  private static final String DEFAULT_ID_ATTRIBUTE = "cn";
  private static final String DEFAULT_MEMBER_ATTRIBUTE = "uniqueMember";
  private static final String DEFAULT_REQUEST = "(&(objectClass=groupOfUniqueNames)(uniqueMember={dn}))";

  private final String baseDn;
  private final String idAttribute;
  private final String request;
  private final String[] requiredUserAttributes;
  private final String[] groupRequestServersOverride;

  /**
   * Constructs mapping from Sonar settings.
   */
  public LdapGroupMapping(Settings settings, String settingsRootKey, String serverKey, String[] availableServers) {  
    String settingsPrefix = settingsRootKey + (serverKey != null ? "." + serverKey : "");
    this.baseDn = settings.getString(settingsPrefix + ".group.baseDn");
    this.idAttribute = StringUtils.defaultString(settings.getString(settingsPrefix + ".group.idAttribute"), DEFAULT_ID_ATTRIBUTE);

    String objectClass = settings.getString(settingsPrefix + ".group.objectClass");
    String memberAttribute = settings.getString(settingsPrefix + ".group.memberAttribute");

    String req;
    if (StringUtils.isNotBlank(objectClass) || StringUtils.isNotBlank(memberAttribute)) {
      // For backward compatibility with plugin versions 1.1 and 1.1.1
      objectClass = StringUtils.defaultString(objectClass, DEFAULT_OBJECT_CLASS);
      memberAttribute = StringUtils.defaultString(memberAttribute, DEFAULT_MEMBER_ATTRIBUTE);
      req = "(&(objectClass=" + objectClass + ")(" + memberAttribute + "=" + "{dn}))";
      LoggerFactory.getLogger(LdapGroupMapping.class)
          .warn("Properties '" + settingsPrefix + ".group.objectClass' and '" + settingsPrefix + ".group.memberAttribute' are deprecated" +
            " and should be replaced by single property '" + settingsPrefix + ".group.request' with value: " + req);
    } else {
      req = StringUtils.defaultString(settings.getString(settingsPrefix + ".group.request"), DEFAULT_REQUEST);
    }
    this.requiredUserAttributes = StringUtils.substringsBetween(req, "{", "}");
    for (int i = 0; i < requiredUserAttributes.length; i++) {
      req = StringUtils.replace(req, "{" + requiredUserAttributes[i] + "}", "{" + i + "}");
    }
    this.request = req;
    
    String groupSearchPropertyName = settingsPrefix + ".group.searchServers";
    String[] groupSearchServers = settings.getStringArray(groupSearchPropertyName);
    if (groupSearchServers.length > 0) {
      Set<String> available = new HashSet<String>(Arrays.asList(availableServers));
      Set<String> configured = new HashSet<String>(Arrays.asList(groupSearchServers));
      configured.removeAll(available);
      if (!configured.isEmpty())
      {
        throw new SonarException(String.format("The property '%s' property contains server names not configured.", groupSearchPropertyName));
      }
      this.groupRequestServersOverride = groupSearchServers;
    } else {
      this.groupRequestServersOverride = null;
    }
  }

  /**
   * Search for this mapping.
   */
  public LdapSearch createSearch(LdapContextFactory contextFactory, SearchResult user) {
    String[] attrs = getRequiredUserAttributes();
    String[] parameters = new String[attrs.length];
    for (int i = 0; i < parameters.length; i++) {
      String attr = attrs[i];
      if ("dn".equals(attr)) {
        parameters[i] = user.getNameInNamespace();
      } else if ("objectsid".equals(attr.toLowerCase())) {
    	Attribute attribute = user.getAttributes().get(attr);
		byte[] objectSid;
		try {
			objectSid = (byte[])attribute.get();
			PSID sid = new PSID(objectSid);
			parameters[i] = Advapi32Util.convertSidToStringSid(sid);
		} catch (NamingException e) {
			// TODO Auto-generated catch block
			parameters[i] = null;
		}
      } else {
        parameters[i] = getAttributeValue(user, attr);
      }
    }
    return new LdapSearch(contextFactory)
        .setBaseDn(getBaseDn())
        .setRequest(getRequest())
        .setParameters(parameters)
        .returns(getIdAttribute());
  }

  private static String getAttributeValue(SearchResult user, String attributeId) {
    Attribute attribute = user.getAttributes().get(attributeId);
    if (attribute == null) {
      return null;
    }
    try {
      return (String) attribute.get();
    } catch (NamingException e) {
      throw new SonarException(e);
    }
  }

  /**
   * Base DN. For example "ou=groups,o=mycompany".
   */
  public String getBaseDn() {
    return baseDn;
  }

  /**
   * Group ID Attribute. For example "cn".
   */
  public String getIdAttribute() {
    return idAttribute;
  }

  /**
   * Request. For example:
   * <pre>
   * (&(objectClass=groupOfUniqueNames)(uniqueMember={0}))
   * (&(objectClass=posixGroup)(memberUid={0}))
   * (&(|(objectClass=groupOfUniqueNames)(objectClass=posixGroup))(|(uniqueMember={0})(memberUid={1})))
   * </pre>
   */
  public String getRequest() {
    return request;
  }

  /**
   * Attributes of user required for search of groups.
   */
  public String[] getRequiredUserAttributes() {
    return requiredUserAttributes;
  }
  
  /**
   * List of servers to search groups from.
   */
  public String[] getGroupRequestServersOverride() {
    return groupRequestServersOverride;
  }

  @Override
  public String toString() {
    return Objects.toStringHelper(this)
        .add("baseDn", getBaseDn())
        .add("idAttribute", getIdAttribute())
        .add("requiredUserAttributes", Arrays.toString(getRequiredUserAttributes()))
        .add("request", getRequest())
        .toString();
  }

}
