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

import com.google.common.base.Objects;
import org.apache.commons.lang.StringUtils;
import org.sonar.api.config.Settings;

/**
 * @author Evgeny Mandrikov
 */
public class LdapGroupMapping {

  private static final String DEFAULT_OBJECT_CLASS = "groupOfUniqueNames";
  private static final String DEFAULT_ID_ATTRIBUTE = "cn";
  private static final String DEFAULT_MEMBER_ATTRIBUTE = "uniqueMember";
  private static final String DEFAULT_MEMBER_FORMAT = null;
  private final String baseDn;
  private final String objectClass;
  private final String idAttribute;
  private final String memberAttribute;
  private final String memberFormat;

  /**
   * Constructs mapping from Sonar settings.
   */
  public LdapGroupMapping(Settings settings) {
    this.baseDn = settings.getString("ldap.group.baseDn");
    this.objectClass = StringUtils.defaultString(settings.getString("ldap.group.objectClass"), DEFAULT_OBJECT_CLASS);
    this.idAttribute = StringUtils.defaultString(settings.getString("ldap.group.idAttribute"), DEFAULT_ID_ATTRIBUTE);
    this.memberAttribute = StringUtils.defaultString(settings.getString("ldap.group.memberAttribute"), DEFAULT_MEMBER_ATTRIBUTE);
    this.memberFormat = StringUtils.defaultString(settings.getString("ldap.group.memberFormat"), DEFAULT_MEMBER_FORMAT);
  }

  /**
   * Search for this mapping.
   */
  public LdapSearch createSearch(LdapContextFactory contextFactory, String username) {
    return new LdapSearch(contextFactory)
        .setBaseDn(getBaseDn())
        .setRequest("(&(objectClass=" + getObjectClass() + ")(" + getMemberAttribute() + "={0}))")
        .setParameters(StringUtils.replace(getMemberFormat(), "$username", username))
        .setReturningAttributes(getIdAttribute());
  }

  /**
   * Base DN. For example "ou=groups,o=mycompany".
   */
  public String getBaseDn() {
    return baseDn;
  }

  /**
   * Object Class. For example "groupOfUniqueNames".
   */
  public String getObjectClass() {
    return objectClass;
  }

  /**
   * Group ID Attribute. For example "cn".
   */
  public String getIdAttribute() {
    return idAttribute;
  }

  /**
   * Group Member Attribute. For example "uniqueMember".
   */
  public String getMemberAttribute() {
    return memberAttribute;
  }

  /**
   * Group Member Format. For example "uid=$username,ou=users,o=mycompany".
   */
  public String getMemberFormat() {
    return memberFormat;
  }

  @Override
  public String toString() {
    return Objects.toStringHelper(this)
        .add("baseDn", getBaseDn())
        .add("objectClass", getObjectClass())
        .add("idAttribute", getIdAttribute())
        .add("memberAttribute", getMemberAttribute())
        .add("memberFormat", getMemberFormat())
        .toString();
  }

}
