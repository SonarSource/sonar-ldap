/*
 * SonarQube LDAP Plugin
 * Copyright (C) 2009-2016 SonarSource SA
 * mailto:contact AT sonarsource DOT com
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
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
package org.sonar.plugins.ldap;

import com.google.common.base.MoreObjects;
import java.util.Arrays;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.SearchResult;
import org.apache.commons.lang.StringUtils;
import org.slf4j.LoggerFactory;

/**
 * @author Evgeny Mandrikov
 */
public class LdapGroupMapping {
  private final String baseDn;
  private final String idAttribute;
  private final String request;
  private final String[] requiredUserAttributes;

  /**
   * Constructs mapping from Sonar settings.
   */
  public LdapGroupMapping(LdapSettings settings, String settingsPrefix) {
    String userGroupsBaseDn = settings.getUserGroupBaseDn(settingsPrefix);
    if (userGroupsBaseDn == null) {
      String realm = settings.getLdapRealm(settingsPrefix);
      Boolean autoDiscoveryEnabled = settings.isAutoDiscoveryEnabled();
      if (realm != null && autoDiscoveryEnabled) {
        userGroupsBaseDn = LdapAutodiscovery.getDnsDomainDn(realm);
      }
    }
    this.baseDn = userGroupsBaseDn;
    this.idAttribute = settings.getUserGroupIdAttributeOrDefault(settingsPrefix);

    String req = getUserGroupRequestQuery(settings, settingsPrefix);
    this.requiredUserAttributes = StringUtils.substringsBetween(req, "{", "}");
    for (int i = 0; i < requiredUserAttributes.length; i++) {
      req = StringUtils.replace(req, "{" + requiredUserAttributes[i] + "}", "{" + i + "}");
    }
    this.request = req;
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
      throw new IllegalArgumentException(e);
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

  @Override
  public String toString() {
    return MoreObjects.toStringHelper(this)
      .add("baseDn", getBaseDn())
      .add("idAttribute", getIdAttribute())
      .add("requiredUserAttributes", Arrays.toString(getRequiredUserAttributes()))
      .add("request", getRequest())
      .toString();
  }

  private String getUserGroupRequestQuery(LdapSettings settings, String settingsPrefix) {
    String req;

    String objectClass = settings.getUserGroupObjectClass(settingsPrefix);
    String memberAttribute = settings.getUserGroupMemberAttribute(settingsPrefix);
    if (StringUtils.isNotBlank(objectClass) || StringUtils.isNotBlank(memberAttribute)) {
      // For backward compatibility with plugin versions 1.1 and 1.1.1
      objectClass = settings.getUserGroupObjectClassOrDefault(settingsPrefix);
      memberAttribute = settings.getUserGroupMemberAttributeOrDefault(settingsPrefix);

      req = "(&(objectClass=" + objectClass + ")(" + memberAttribute + "=" + "{dn}))";

      LoggerFactory.getLogger(LdapGroupMapping.class)
        .warn("Properties '" + settingsPrefix + ".group.objectClass' and '" + settingsPrefix + ".group.memberAttribute' are deprecated" +
          " and should be replaced by single property '" + settingsPrefix + ".group.request' with value: " + req);
    } else {
      req = settings.getUserGroupRequestOrDefault(settingsPrefix);
    }

    return req;
  }

}
