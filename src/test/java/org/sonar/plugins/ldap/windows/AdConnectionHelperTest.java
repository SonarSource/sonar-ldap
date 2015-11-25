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

import com4j.ComException;
import com4j.typelibs.activeDirectory.IADs;
import com4j.typelibs.ado20.Field;
import com4j.typelibs.ado20.Fields;
import com4j.typelibs.ado20._Command;
import com4j.typelibs.ado20._Connection;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import javax.annotation.Nullable;
import org.apache.commons.lang.StringUtils;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.sonar.plugins.ldap.windows.auth.ICom4jWrapper;
import org.sonar.plugins.ldap.windows.stubs.com4j.RecordSetStub;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class AdConnectionHelperTest {
  private AdConnectionHelper adConnectionHelper;
  private ICom4jWrapper com4jWrapper;
  private Collection<String> userAttributesForGetUserDetailsTests;
  private Collection<String> userAttributesForGetUserGroupTests;
  private String testRequestedGroupIdAttribute;
  private String domainName;
  private String userName;
  private String namingContext;
  private String userDistinguishedName;
  private String adBindString;

  @Before
  public void init() {
    com4jWrapper = mock(ICom4jWrapper.class);
    adConnectionHelper = new AdConnectionHelper(com4jWrapper);
    userAttributesForGetUserDetailsTests = getRequestedUserAttributesForGetUserDetailsTests();
    userAttributesForGetUserGroupTests = getRequestedUserAttributesForGetUserGroupsTests();
    testRequestedGroupIdAttribute = "someAttribute";
    domainName = "domain";
    userName = "userName";
    namingContext = "dc=domain";
    userDistinguishedName = "dn=User Distinguished Name";
    adBindString = "LDAP://" + domainName + "/" + namingContext;
  }

  @Test(expected = IllegalArgumentException.class)
  public void getUserDetailsDomainNameNullArgumentCheck() {
    adConnectionHelper.getUserDetails(null, userName, userAttributesForGetUserDetailsTests);
  }

  @Test(expected = IllegalArgumentException.class)
  public void getUserDetailsDomainNameEmptyArgumentCheck() {
    adConnectionHelper.getUserDetails("", userName, userAttributesForGetUserDetailsTests);
  }

  @Test(expected = IllegalArgumentException.class)
  public void getUserDetailsUserNameNullArgumentCheck() {
    adConnectionHelper.getUserDetails(domainName, null, userAttributesForGetUserDetailsTests);
  }

  @Test(expected = IllegalArgumentException.class)
  public void getUserDetailsUserNameEmptyArgumentCheck() {
    adConnectionHelper.getUserDetails(domainName, "", userAttributesForGetUserDetailsTests);
  }

  @Test(expected = IllegalArgumentException.class)
  public void getUserDetailsRequestedAttributesNullArgumentCheck() {
    adConnectionHelper.getUserDetails(domainName, userName, null);
  }

  @Test(expected = IllegalArgumentException.class)
  public void getUserDetailsRequestedAttributesEmptyArgumentCheck() {
    adConnectionHelper.getUserDetails(domainName, userName, new ArrayList<String>());
  }

  @Test
  public void getUserDetailsWhenGetConnectionUrlReturnsNull() {
    String testConnectionString = getTestConnectionString(domainName);
    when(com4jWrapper.getObject(IADs.class, testConnectionString,
      null)).thenThrow(mock(ComException.class));

    assertThat(adConnectionHelper.getUserDetails(domainName, userName, userAttributesForGetUserDetailsTests)).isEmpty();

    verify(com4jWrapper, times(1)).cleanUp();
  }

  @Test
  public void getUserDetailsWhenGetActiveDirectoryReturnsNull() {
    setupTestDefaultNamingContext(domainName, namingContext);

    when(com4jWrapper.createConnection()).thenReturn(null);

    assertThat(adConnectionHelper.getUserDetails(domainName, userName, userAttributesForGetUserDetailsTests)).isEmpty();

    verify(com4jWrapper, times(1)).cleanUp();
  }

  @Test
  public void getUserDetailsWhenCom4JWrapperExecuteCommandReturnsNull() {
    setupTestDefaultNamingContext(domainName, namingContext);

    String commandText = getUserDetailsCommandText(adBindString, userName, userAttributesForGetUserDetailsTests);

    _Connection connection = mock(_Connection.class);
    when(com4jWrapper.createConnection()).thenReturn(connection);
    when(com4jWrapper.createCommand(connection, commandText)).thenReturn(null);
    when(connection.execute(null, com4jWrapper.getMissing(), -1)).thenReturn(null);

    assertThat(adConnectionHelper.getUserDetails(domainName, userName, userAttributesForGetUserDetailsTests)).isEmpty();
    verify(com4jWrapper, times(1)).createCommand(connection, commandText);
    verify(com4jWrapper, times(1)).cleanUp();
  }

  @Test
  public void getUserDetailsWhenCom4jWrapperExecuteCommandThrowsException() {
    setupTestDefaultNamingContext(domainName, namingContext);
    String commandText = getUserDetailsCommandText(adBindString, userName, userAttributesForGetUserDetailsTests);

    // ExecuteCommand returns null as executeCommand throws exception
    _Connection connection = mock(_Connection.class);
    when(com4jWrapper.createConnection()).thenReturn(connection);

    ComException comException = mock(ComException.class);
    when(comException.getMessage()).thenReturn("Com4jComException: Exception");

    _Command command = mock(_Command.class);
    when(com4jWrapper.createCommand(connection, commandText)).thenReturn(command);
    when(command.execute(null, com4jWrapper.getMissing(), -1)).thenThrow(comException);

    assertThat(adConnectionHelper.getUserDetails(domainName, userName, userAttributesForGetUserDetailsTests)).isEmpty();
    verify(com4jWrapper, times(1)).createCommand(connection, commandText);
    verify(com4jWrapper, times(1)).cleanUp();
    verify(comException, times(1)).getMessage();
  }

  @Test
  public void getUserDetailsWhenExecuteCommandReturnsNullRecordSet() {
    setupTestDefaultNamingContext(domainName, namingContext);
    _Connection connection = mock(_Connection.class);
    when(com4jWrapper.createConnection()).thenReturn(connection);

    String commandText = getUserDetailsCommandText(adBindString, userName, userAttributesForGetUserDetailsTests);

    _Command command = mock(_Command.class);
    when(command.execute(null, com4jWrapper.getMissing(), -1)).thenReturn(null);
    when(com4jWrapper.createCommand(connection, commandText)).thenReturn(command);

    assertThat(adConnectionHelper.getUserDetails(domainName, userName, userAttributesForGetUserDetailsTests)).isEmpty();
    verify(com4jWrapper, times(1)).createCommand(connection, commandText);
    verify(command, times(1)).dispose();
    verify(com4jWrapper, times(1)).cleanUp();
  }

  @Test
  public void getUserDetailsWhenRecordSetEofIsNotSet() {
    setupTestDefaultNamingContext(domainName, namingContext);
    _Connection connection = mock(_Connection.class);
    when(com4jWrapper.createConnection()).thenReturn(connection);

    String commandText = getUserDetailsCommandText(adBindString, userName, userAttributesForGetUserDetailsTests);

    RecordSetStub recordSet = getTestRecordSet(null);
    _Command command = mock(_Command.class);
    when(command.execute(null, com4jWrapper.getMissing(), -1)).thenReturn(recordSet);
    when(com4jWrapper.createCommand(connection, commandText)).thenReturn(command);

    assertThat(adConnectionHelper.getUserDetails(domainName, userName, userAttributesForGetUserDetailsTests)).isEmpty();
    verify(command, times(1)).dispose();

    assertThat(recordSet.getDisposeInvocationCount()).isEqualTo(1);
    assertThat(recordSet.getCloseInvocationCount()).isEqualTo(1);

    verify(com4jWrapper, times(1)).createCommand(connection, commandText);
    verify(com4jWrapper, times(1)).cleanUp();
  }

  @Test
  public void getUserDetailsNormalTest() {
    setupTestDefaultNamingContext(domainName, namingContext);
    _Connection connection = mock(_Connection.class);
    when(com4jWrapper.createConnection()).thenReturn(connection);

    String commandText = getUserDetailsCommandText(adBindString, userName, userAttributesForGetUserDetailsTests);

    Collection<Map<String, String>> fieldsRows = new ArrayList<>();
    Map<String, String> fieldsCollection = new HashMap<>();
    fieldsCollection.put(AdConnectionHelper.COMMON_NAME_ATTRIBUTE, "Full Name");
    fieldsCollection.put(AdConnectionHelper.MAIL_ATTRIBUTE, "abc@example.org");
    fieldsRows.add(fieldsCollection);

    RecordSetStub recordSet = getTestRecordSet(fieldsRows);
    _Command command = mock(_Command.class);
    when(command.execute(null, com4jWrapper.getMissing(), -1)).thenReturn(recordSet);
    when(com4jWrapper.createCommand(connection, commandText)).thenReturn(command);

    Map<String, String> userDetails = adConnectionHelper.getUserDetails(domainName, userName, userAttributesForGetUserDetailsTests);

    assertThat(userDetails).isEqualTo(fieldsCollection);
    verify(command, times(1)).dispose();
    assertThat(recordSet.getDisposeInvocationCount()).isEqualTo(1);
    assertThat(recordSet.getCloseInvocationCount()).isEqualTo(1);
    verify(com4jWrapper, times(1)).createCommand(connection, commandText);
    verify(com4jWrapper, times(1)).cleanUp();
  }

  @Test(expected = IllegalArgumentException.class)
  public void getUserGroupsDomainNameNullArgumentCheck() {
    adConnectionHelper.getUserGroupsInDomain(null, userName, testRequestedGroupIdAttribute);
  }

  @Test(expected = IllegalArgumentException.class)
  public void getUserGroupsDomainNameEmptyArgumentCheck() {
    adConnectionHelper.getUserGroupsInDomain("", userName, testRequestedGroupIdAttribute);
  }

  @Test(expected = IllegalArgumentException.class)
  public void getUserGroupsUserNameNullArgumentCheck() {
    adConnectionHelper.getUserGroupsInDomain(domainName, null, testRequestedGroupIdAttribute);
  }

  @Test(expected = IllegalArgumentException.class)
  public void getUserGroupsUserNameEmptyArgumentCheck() {
    adConnectionHelper.getUserGroupsInDomain(domainName, "", testRequestedGroupIdAttribute);
  }

  @Test(expected = IllegalArgumentException.class)
  public void getUserGroupsRequestedAttributesNullArgumentCheck() {
    adConnectionHelper.getUserGroupsInDomain(domainName, userName, null);
  }

  @Test(expected = IllegalArgumentException.class)
  public void getUserGroupsRequestedAttributesEmptyArgumentCheck() {
    adConnectionHelper.getUserGroupsInDomain(domainName, userName, "");
  }

  @Test
  public void getUserGroupsWhenGetDefaultNamingContextReturnsNull() {
    String testConnectionString = getTestConnectionString(domainName);
    when(com4jWrapper.getObject(IADs.class, testConnectionString, null)).thenThrow(mock(ComException.class));

    assertThat(adConnectionHelper.getUserGroupsInDomain(domainName, userName, testRequestedGroupIdAttribute)).isEmpty();

    verify(com4jWrapper, times(1)).cleanUp();
  }

  @Test
  public void getUserGroupsWhenGetActiveDirectoryReturnsNull() {
    setupTestDefaultNamingContext(domainName, namingContext);

    when(com4jWrapper.createConnection()).thenReturn(null);

    assertThat(adConnectionHelper.getUserGroupsInDomain(domainName, userName, testRequestedGroupIdAttribute)).isEmpty();
    verify(com4jWrapper, times(1)).cleanUp();
  }

  @Test
  public void getUserGroupsWhenExecuteCommandReturnsNull() {
    setupTestDefaultNamingContext(domainName, namingContext);
    _Connection connection = mock(_Connection.class);
    when(com4jWrapper.createConnection()).thenReturn(connection);

    String commandText = getUserDetailsCommandText(adBindString, userName, userAttributesForGetUserGroupTests);

    when(com4jWrapper.createCommand(connection, commandText)).thenReturn(null);

    assertThat(adConnectionHelper.getUserGroupsInDomain(domainName, userName, testRequestedGroupIdAttribute)).isEmpty();
    verify(com4jWrapper, times(1)).createCommand(connection, commandText);
    verify(com4jWrapper, times(1)).cleanUp();
  }

  @Test
  public void getUserGroupsWhenExecuteCommandFroUserDetailsReturnsNullRecordSet() {
    setupTestDefaultNamingContext(domainName, namingContext);

    _Connection connection = mock(_Connection.class);
    when(com4jWrapper.createConnection()).thenReturn(connection);

    String commandText = getUserDetailsCommandText(adBindString, userName, userAttributesForGetUserGroupTests);

    _Command command = mock(_Command.class);
    when(command.execute(null, com4jWrapper.getMissing(), -1)).thenReturn(null);
    when(com4jWrapper.createCommand(connection, commandText)).thenReturn(command);

    assertThat(adConnectionHelper.getUserGroupsInDomain(domainName, userName, testRequestedGroupIdAttribute)).isEmpty();
    verify(com4jWrapper, times(1)).createCommand(connection, commandText);
    verify(command, times(1)).dispose();
    verify(com4jWrapper, times(1)).cleanUp();
  }

  @Test
  public void getUserGroupsWhenUserDetailsRecordSetEofIsNotSet() {
    setupTestDefaultNamingContext(domainName, namingContext);
    _Connection connection = mock(_Connection.class);
    when(com4jWrapper.createConnection()).thenReturn(connection);

    String commandText = getUserDetailsCommandText(adBindString, userName, userAttributesForGetUserGroupTests);

    RecordSetStub recordSet = getTestRecordSet(null);
    _Command command = mock(_Command.class);
    when(command.execute(null, com4jWrapper.getMissing(), -1)).thenReturn(recordSet);
    when(com4jWrapper.createCommand(connection, commandText)).thenReturn(command);

    assertThat(adConnectionHelper.getUserGroupsInDomain(domainName, userName, testRequestedGroupIdAttribute)).isEmpty();
    verify(command, times(1)).dispose();

    assertThat(recordSet.getDisposeInvocationCount()).isEqualTo(1);
    assertThat(recordSet.getCloseInvocationCount()).isEqualTo(1);

    verify(com4jWrapper, times(1)).createCommand(connection, commandText);
    verify(com4jWrapper, times(1)).cleanUp();
  }

  @Test
  public void getUserGroupsNormalTest() {
    setupTestDefaultNamingContext(domainName, namingContext);
    _Connection connection = mock(_Connection.class);
    when(com4jWrapper.createConnection()).thenReturn(connection);

    // Setup User Details
    Collection<Map<String, String>> userDetailsRows = new ArrayList<>();
    Map<String, String> userDetailsFieldsCollection = new HashMap<>();
    userDetailsFieldsCollection.put(AdConnectionHelper.DISTINGUISHED_NAME_STR, userDistinguishedName);
    userDetailsRows.add(userDetailsFieldsCollection);
    RecordSetStub userDetailsRecordSet = getTestRecordSet(userDetailsRows);

    String userDetailsCommandText = getUserDetailsCommandText(adBindString, userName, userAttributesForGetUserGroupTests);

    _Command userDetailsCommand = mock(_Command.class);
    when(userDetailsCommand.execute(null, com4jWrapper.getMissing(), -1)).thenReturn(userDetailsRecordSet);
    when(com4jWrapper.createCommand(connection, userDetailsCommandText)).thenReturn(userDetailsCommand);

    // Setup User Groups
    Collection<Map<String, String>> userGroupsRows = new ArrayList<>();
    Map<String, String> userGroupFieldsCollection1 = new HashMap<>();
    userGroupFieldsCollection1.put(testRequestedGroupIdAttribute, "Group1");
    userGroupsRows.add(userGroupFieldsCollection1);

    Map<String, String> userGroupFieldsCollection2 = new HashMap<>();
    userGroupFieldsCollection2.put(testRequestedGroupIdAttribute, "Group2");
    userGroupsRows.add(userGroupFieldsCollection2);

    Collection<String> expectedUserGroups = new ArrayList<>();
    expectedUserGroups.add("Group1");
    expectedUserGroups.add("Group2");
    RecordSetStub userGroupsRecordSet = getTestRecordSet(userGroupsRows);

    String userGroupsCommandText = getUserGroupsCommandText(adBindString, userDistinguishedName, testRequestedGroupIdAttribute);
    _Command userGroupsCommand = mock(_Command.class);
    when(userGroupsCommand.execute(null, com4jWrapper.getMissing(), -1)).thenReturn(userGroupsRecordSet);
    when(com4jWrapper.createCommand(connection, userGroupsCommandText)).thenReturn(userGroupsCommand);

    Collection<String> userGroups = adConnectionHelper.getUserGroupsInDomain(domainName, userName,
      testRequestedGroupIdAttribute);

    assertThat(userGroups).isEqualTo(expectedUserGroups);

    verify(userDetailsCommand, times(1)).dispose();
    verify(userGroupsCommand, times(1)).dispose();

    assertThat(userDetailsRecordSet.getDisposeInvocationCount()).isEqualTo(1);
    assertThat(userDetailsRecordSet.getCloseInvocationCount()).isEqualTo(1);

    assertThat(userGroupsRecordSet.getDisposeInvocationCount()).isEqualTo(1);
    assertThat(userGroupsRecordSet.getCloseInvocationCount()).isEqualTo(1);

    verify(com4jWrapper, times(1)).createCommand(connection, userGroupsCommandText);
    verify(com4jWrapper, times(1)).createCommand(connection, userDetailsCommandText);

    verify(com4jWrapper, times(1)).cleanUp();
  }

  @Test
  public void getActiveDirectoryConnectionOpenThrowsComException() {
    ComException comException = mock(ComException.class);
    when(comException.getMessage()).thenReturn("ComException");

    _Connection connection = mock(_Connection.class);
    Mockito.doThrow(comException).when(connection).open(AdConnectionHelper.DEFAULT_AD_CONNECTION_STR, "", "", -1);
    when(com4jWrapper.createConnection()).thenReturn(connection);

    assertThat(adConnectionHelper.getActiveDirectoryConnection()).isNull();
    verify(comException, times(1)).getMessage();
  }

  @Test
  public void getActiveDirectoryConnectionCreateConnectionReturnsNull() {
    when(com4jWrapper.createConnection()).thenReturn(null);

    assertThat(adConnectionHelper.getActiveDirectoryConnection()).isNull();
  }

  @Test
  public void getActiveDirectoryConnectionNormalTest() {
    _Connection connection = mock(_Connection.class);
    when(com4jWrapper.createConnection()).thenReturn(connection);

    assertThat(adConnectionHelper.getActiveDirectoryConnection()).isEqualTo(connection);
  }

  @Test
  public void getConnectionUrlTestCom4jGetObjectThrowsComException() {
    String testConnectionString = getTestConnectionString(domainName);
    ComException comException = mock(ComException.class);
    when(comException.getMessage()).thenReturn("ComException");
    when(com4jWrapper.getObject(IADs.class, testConnectionString,
      null)).thenThrow(comException);

    String bindString = adConnectionHelper.getActiveDirectoryBindString(domainName);

    assertThat(bindString).isNull();
    verify(com4jWrapper, times(1)).getObject(IADs.class, testConnectionString, null);
    verify(comException, times(1)).getMessage();
  }

  @Test
  public void getConnectionUrlTestRootDseGetThrowsComException() {
    String testConnectionString = getTestConnectionString(domainName);
    ComException comException = mock(ComException.class);
    when(comException.getMessage()).thenReturn("ComException");
    IADs iads = mock(IADs.class);
    when(iads.get(AdConnectionHelper.DEFAULT_NAMING_CONTEXT_STR)).thenThrow(comException);
    when(com4jWrapper.getObject(IADs.class, testConnectionString, null)).thenReturn(iads);

    String bindString = adConnectionHelper.getActiveDirectoryBindString(domainName);

    assertThat(bindString).isNull();
    verify(com4jWrapper, times(1)).getObject(IADs.class, testConnectionString, null);
    verify(comException, times(1)).getMessage();
  }

  @Test
  public void getConnectionUrlNormalTest() {
    setupTestDefaultNamingContext(domainName, namingContext);

    assertThat(adConnectionHelper.getActiveDirectoryBindString(domainName)).isEqualTo(adBindString);
  }

  @Test
  public void getUserAttributeValueFieldsItemIsNull() {
    Fields fields = mock(Fields.class);
    when(fields.item(AdConnectionHelper.COMMON_NAME_ATTRIBUTE)).thenReturn(null);
    assertThat(adConnectionHelper.getUserAttributeValue(fields, AdConnectionHelper.COMMON_NAME_ATTRIBUTE)).isNull();
  }

  @Test
  public void getUserAttributeValueFieldsItemThrowComException() {
    ComException comException = mock(ComException.class);
    when(comException.getMessage()).thenReturn("COMException is thrown");

    Fields fields = mock(Fields.class);
    when(fields.item(AdConnectionHelper.COMMON_NAME_ATTRIBUTE)).thenThrow(comException);
    assertThat(adConnectionHelper.getUserAttributeValue(fields, AdConnectionHelper.COMMON_NAME_ATTRIBUTE)).isNull();
    verify(comException, times(1)).getMessage();
  }

  @Test
  public void getUserAttributeValueFieldsItemValueIsNull() {
    Field field = mock(Field.class);
    when(field.value()).thenReturn(null);

    Fields fields = mock(Fields.class);
    when(fields.item(AdConnectionHelper.COMMON_NAME_ATTRIBUTE)).thenReturn(field);

    assertThat(adConnectionHelper.getUserAttributeValue(fields, AdConnectionHelper.COMMON_NAME_ATTRIBUTE)).isNull();
  }

  @Test
  public void getUserAttributeValueNormalTest() {
    String fullName = "Full Name";
    String mail = "abc@example.org";
    Map<String, String> fieldsCollection = new HashMap<>();
    fieldsCollection.put(AdConnectionHelper.COMMON_NAME_ATTRIBUTE, fullName);
    fieldsCollection.put(AdConnectionHelper.MAIL_ATTRIBUTE, mail);
    Fields fields = getTestFields(fieldsCollection);

    assertThat(adConnectionHelper.getUserAttributeValue(fields, AdConnectionHelper.COMMON_NAME_ATTRIBUTE)).isEqualTo(fullName);

    assertThat(adConnectionHelper.getUserAttributeValue(fields, AdConnectionHelper.MAIL_ATTRIBUTE)).isEqualTo(mail);
  }

  private String getTestConnectionString(final String domainName) {
    return "LDAP://" + domainName + "/" + AdConnectionHelper.ROOT_DSE;
  }

  private String getUserDetailsCommandText(final String bindString, final String userName, final Collection<String> requestedDetails) {
    /* Requested user attributes */
    String requestedAttributes = StringUtils.join(requestedDetails, ",");

    return String.format("<%s>;(%s=%s);%s;SubTree", bindString, AdConnectionHelper.SAMACCOUNTNAME_STR, userName,
      requestedAttributes);
  }

  private String getUserGroupsCommandText(final String bindString, final String userDistinguishedName,
    final String requestedGroupIdAttribute) {
    String filter = String.format("(&(objectClass=group)(member=%s))", userDistinguishedName);
    return String.format("<%s>;%s;%s;SubTree", bindString, filter, testRequestedGroupIdAttribute);
  }

  private Collection<String> getRequestedUserAttributesForGetUserDetailsTests() {
    Collection<String> requestedAttributes = new ArrayList<>();
    requestedAttributes.add(AdConnectionHelper.COMMON_NAME_ATTRIBUTE);
    requestedAttributes.add(AdConnectionHelper.MAIL_ATTRIBUTE);

    return requestedAttributes;
  }

  private Collection<String> getRequestedUserAttributesForGetUserGroupsTests() {
    Collection<String> requestedAttributes = new ArrayList<>();
    requestedAttributes.add(AdConnectionHelper.DISTINGUISHED_NAME_STR);

    return requestedAttributes;
  }

  private RecordSetStub getTestRecordSet(@Nullable Collection<Map<String, String>> fieldsRows) {
    Collection<Fields> fieldsRowList = new ArrayList<>();

    if (fieldsRows != null) {
      for (Map<String, String> fieldsCollection : fieldsRows) {
        fieldsRowList.add(getTestFields(fieldsCollection));
      }
    }

    return new RecordSetStub(fieldsRowList);
  }

  private Fields getTestFields(final Map<String, String> fieldsCollection) {
    Fields fields = mock(Fields.class);

    for (String fieldName : fieldsCollection.keySet()) {
      Field field = getTestField(fieldsCollection.get(fieldName));
      when(fields.item(fieldName)).thenReturn(field);
    }

    return fields;
  }

  private Field getTestField(final String fieldValue) {
    Field field = mock(Field.class);
    when(field.value()).thenReturn(fieldValue);

    return field;
  }

  private void setupTestDefaultNamingContext(final String domainName, final String defaultNamingContext) {
    String testConnectionString = getTestConnectionString(domainName);
    IADs iads = mock(IADs.class);
    when(iads.get(AdConnectionHelper.DEFAULT_NAMING_CONTEXT_STR)).thenReturn(defaultNamingContext);
    when(com4jWrapper.getObject(IADs.class, testConnectionString, null)).thenReturn(iads);
  }
}
