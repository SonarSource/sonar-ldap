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
package org.sonar.plugins.ldap.windows;

import com4j.ComException;
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
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.sonar.plugins.ldap.windows.auth.ICom4jWrapper;

import static org.assertj.core.api.Assertions.assertThat;

public class AdConnectionHelperTest {
  private AdConnectionHelper adConnectionHelper;
  private ICom4jWrapper com4jWrapper;
  private Collection<String> testRequestedUserAttributes;

  @Before
  public void init() {
    com4jWrapper = Mockito.mock(ICom4jWrapper.class);
    adConnectionHelper = new AdConnectionHelper(com4jWrapper);
    testRequestedUserAttributes = getTestRequestedUserAttributes();
  }

  @Test(expected = IllegalArgumentException.class)
  public void getUserDetailsDomainNameNullArgumentCheck() {
    adConnectionHelper.getUserDetails(null, "userName", testRequestedUserAttributes);
  }

  @Test(expected = IllegalArgumentException.class)
  public void getUserDetailsDomainNameEmptyArgumentCheck() {
    adConnectionHelper.getUserDetails("", "userName", testRequestedUserAttributes);
  }

  @Test(expected = IllegalArgumentException.class)
  public void getUserDetailsUserNameNullArgumentCheck() {
    adConnectionHelper.getUserDetails("domain", null, testRequestedUserAttributes);
  }

  @Test(expected = IllegalArgumentException.class)
  public void getUserDetailsUserNameEmptyArgumentCheck() {
    adConnectionHelper.getUserDetails("domain", "", testRequestedUserAttributes);
  }

  @Test(expected = IllegalArgumentException.class)
  public void getUserDetailsRequestedAttributesNullArgumentCheck() {
    adConnectionHelper.getUserDetails("domain", "userName", null);
  }

  @Test(expected = IllegalArgumentException.class)
  public void getUserDetailsRequestedAttributesEmptyArgumentCheck() {
    adConnectionHelper.getUserDetails("domain", "userName", new ArrayList<String>());
  }

  @Test
  public void getUserDetailsWhenGetDefaultNamingContextReturnsNull() {
    String domainName = "domain";
    String testConnectionString = getTestConnectionString(domainName);
    Mockito.when(com4jWrapper.getObject(IADs.class, testConnectionString,
      null)).thenThrow(Mockito.mock(ComException.class));

    assertThat(adConnectionHelper.getUserDetails(domainName, "userName", testRequestedUserAttributes)).isEmpty();

    Mockito.verify(com4jWrapper, Mockito.never()).createCommand();
    Mockito.verify(com4jWrapper, Mockito.times(1)).cleanUp();
  }

  @Test
  public void getUserDetailsWhenGetActiveDirectoryReturnsNull() {
    String domainName = "domain";
    String expectedNamingContext = "dc=domain";
    setupTestDefaultNamingContext(domainName, expectedNamingContext);

    Mockito.when(com4jWrapper.createConnection()).thenReturn(null);

    assertThat(adConnectionHelper.getUserDetails(domainName, "userName", testRequestedUserAttributes)).isEmpty();
    Mockito.verify(com4jWrapper, Mockito.never()).createCommand();
    Mockito.verify(com4jWrapper, Mockito.times(1)).cleanUp();
  }

  @Test
  public void getUserDetailsWhenExecuteCommandReturnsNull() {
    String domainName = "domain";
    String expectedNamingContext = "dc=domain";
    setupTestDefaultNamingContext(domainName, expectedNamingContext);

    Mockito.when(com4jWrapper.createConnection()).thenReturn(Mockito.mock(_Connection.class));
    Mockito.when(com4jWrapper.createCommand()).thenReturn(null);

    assertThat(adConnectionHelper.getUserDetails(domainName, "userName", testRequestedUserAttributes)).isEmpty();
    Mockito.verify(com4jWrapper, Mockito.times(1)).createCommand();
    Mockito.verify(com4jWrapper, Mockito.times(1)).cleanUp();
  }

  @Test
  public void getUserDetailsWhenExecuteCommandReturnsNullRecordSet() {
    String domainName = "domain";
    String expectedNamingContext = "dc=domain";
    setupTestDefaultNamingContext(domainName, expectedNamingContext);

    Mockito.when(com4jWrapper.createConnection()).thenReturn(Mockito.mock(_Connection.class));

    _Command command = Mockito.mock(_Command.class);
    Mockito.when(command.execute(null, com4jWrapper.getMissing(), -1)).thenReturn(null);
    Mockito.when(com4jWrapper.createCommand()).thenReturn(command);

    assertThat(adConnectionHelper.getUserDetails(domainName, "userName", testRequestedUserAttributes)).isEmpty();
    Mockito.verify(com4jWrapper, Mockito.times(1)).createCommand();
    Mockito.verify(command, Mockito.times(1)).dispose();
    Mockito.verify(com4jWrapper, Mockito.times(1)).cleanUp();
  }

  @Test
  public void getUserDetailsWhenRecordSetEofIsNotSet() {
    String domainName = "domain";
    String expectedNamingContext = "dc=domain";
    setupTestDefaultNamingContext(domainName, expectedNamingContext);

    Mockito.when(com4jWrapper.createConnection()).thenReturn(Mockito.mock(_Connection.class));

    _Recordset recordSet = getTestRecordSet(true, null);
    _Command command = Mockito.mock(_Command.class);
    Mockito.when(command.execute(null, com4jWrapper.getMissing(), -1)).thenReturn(recordSet);
    Mockito.when(com4jWrapper.createCommand()).thenReturn(command);

    assertThat(adConnectionHelper.getUserDetails(domainName, "userName", testRequestedUserAttributes)).isEmpty();
    Mockito.verify(command, Mockito.times(1)).dispose();
    Mockito.verify(recordSet, Mockito.times(1)).close();

    Mockito.verify(recordSet, Mockito.times(1)).dispose();
    Mockito.verify(recordSet, Mockito.times(1)).close();
    Mockito.verify(com4jWrapper, Mockito.times(1)).createCommand();
    Mockito.verify(com4jWrapper, Mockito.times(1)).cleanUp();
  }

  @Test
  public void getUserDetailsNormalTest() {
    String domainName = "domain";
    String expectedNamingContext = "dc=domain";
    setupTestDefaultNamingContext(domainName, expectedNamingContext);

    Mockito.when(com4jWrapper.createConnection()).thenReturn(Mockito.mock(_Connection.class));
    Map<String, String> fieldsCollection = new HashMap<String, String>();
    fieldsCollection.put(AdConnectionHelper.COMMON_NAME_ATTRIBUTE, "Full Name");
    fieldsCollection.put(AdConnectionHelper.MAIL_ATTRIBUTE, "abc@example.org");

    _Recordset recordSet = getTestRecordSet(false, fieldsCollection);
    _Command command = Mockito.mock(_Command.class);
    Mockito.when(command.execute(null, com4jWrapper.getMissing(), -1)).thenReturn(recordSet);
    Mockito.when(com4jWrapper.createCommand()).thenReturn(command);
    Map<String, String> userDetails = adConnectionHelper.getUserDetails(domainName, "userName",
      testRequestedUserAttributes);
    assertThat(userDetails).isEqualTo(fieldsCollection);

    Mockito.verify(command, Mockito.times(1)).dispose();
    Mockito.verify(recordSet, Mockito.times(1)).close();

    Mockito.verify(recordSet, Mockito.times(1)).dispose();
    Mockito.verify(recordSet, Mockito.times(1)).close();

    Mockito.verify(com4jWrapper, Mockito.times(1)).createCommand();
    Mockito.verify(com4jWrapper, Mockito.times(1)).cleanUp();
  }

  @Test
  public void getActiveDirectoryConnectionOpenThrowsComException() {
    ComException comException = Mockito.mock(ComException.class);
    Mockito.when(comException.getMessage()).thenReturn("ComException");

    _Connection connection = Mockito.mock(_Connection.class);
    Mockito.doThrow(comException).when(connection).open(AdConnectionHelper.DEFAULT_AD_CONNECTION_STR, "", "", -1);
    Mockito.when(com4jWrapper.createConnection()).thenReturn(connection);

    assertThat(adConnectionHelper.getActiveDirectoryConnection()).isNull();
    Mockito.verify(comException, Mockito.times(1)).getMessage();
  }

  @Test
  public void getActiveDirectoryConnectionCreateConnectionReturnsNull() {
    Mockito.when(com4jWrapper.createConnection()).thenReturn(null);

    assertThat(adConnectionHelper.getActiveDirectoryConnection()).isNull();
  }

  @Test
  public void getActiveDirectoryConnectionNormalTest() {
    _Connection connection = Mockito.mock(_Connection.class);
    Mockito.when(com4jWrapper.createConnection()).thenReturn(connection);

    assertThat(adConnectionHelper.getActiveDirectoryConnection()).isEqualTo(connection);
  }

  @Test
  public void getNamingContextTestCom4jGetObjectThrowsComException() {
    String domainName = "domain";
    String testConnectionString = getTestConnectionString(domainName);
    ComException comException = Mockito.mock(ComException.class);
    Mockito.when(comException.getMessage()).thenReturn("ComException");
    Mockito.when(com4jWrapper.getObject(IADs.class, testConnectionString,
      null)).thenThrow(comException);

    String namingContext = adConnectionHelper.getDefaultNamingContext(domainName);

    assertThat(namingContext).isNull();
    Mockito.verify(com4jWrapper, Mockito.times(1)).getObject(IADs.class, testConnectionString, null);
    Mockito.verify(comException, Mockito.times(1)).getMessage();
  }

  @Test
  public void getNamingContextTestRootDseGetThrowsComException() {
    String domainName = "domain";
    String testConnectionString = getTestConnectionString(domainName);
    ComException comException = Mockito.mock(ComException.class);
    Mockito.when(comException.getMessage()).thenReturn("ComException");
    IADs iads = Mockito.mock(IADs.class);
    Mockito.when(iads.get(AdConnectionHelper.DEFAULT_NAMING_CONTEXT_STR)).thenThrow(comException);
    Mockito.when(com4jWrapper.getObject(IADs.class, testConnectionString, null)).thenReturn(iads);

    String namingContext = adConnectionHelper.getDefaultNamingContext(domainName);

    assertThat(namingContext).isNull();
    Mockito.verify(com4jWrapper, Mockito.times(1)).getObject(IADs.class, testConnectionString, null);
    Mockito.verify(comException, Mockito.times(1)).getMessage();
  }

  @Test
  public void getNamingContextNormalTest() {
    String domainName = "domain";
    String expectedNamingContext = "dc=domain";
    setupTestDefaultNamingContext(domainName, expectedNamingContext);

    assertThat(adConnectionHelper.getDefaultNamingContext(domainName)).isEqualTo(expectedNamingContext);
  }

  @Test
  public void getUserAttributeValueFieldsItemIsNull() {
    Fields fields = Mockito.mock(Fields.class);
    Mockito.when(fields.item(AdConnectionHelper.COMMON_NAME_ATTRIBUTE)).thenReturn(null);
    assertThat(adConnectionHelper.getUserAttributeValue(fields, AdConnectionHelper.COMMON_NAME_ATTRIBUTE)).isNull();
  }

  @Test
  public void getUserAttributeValueFieldsItemThrowComException() {
    ComException comException = Mockito.mock(ComException.class);
    Mockito.when(comException.getMessage()).thenReturn("COMException is thrown");

    Fields fields = Mockito.mock(Fields.class);
    Mockito.when(fields.item(AdConnectionHelper.COMMON_NAME_ATTRIBUTE)).thenThrow(comException);
    assertThat(adConnectionHelper.getUserAttributeValue(fields, AdConnectionHelper.COMMON_NAME_ATTRIBUTE)).isNull();
    Mockito.verify(comException, Mockito.times(1)).getMessage();
  }

  @Test
  public void getUserAttributeValueFieldsItemValueIsNull() {
    Field field = Mockito.mock(Field.class);
    Mockito.when(field.value()).thenReturn(null);

    Fields fields = Mockito.mock(Fields.class);
    Mockito.when(fields.item(AdConnectionHelper.COMMON_NAME_ATTRIBUTE)).thenReturn(field);

    assertThat(adConnectionHelper.getUserAttributeValue(fields, AdConnectionHelper.COMMON_NAME_ATTRIBUTE)).isNull();
  }

  @Test
  public void getUserAttributeValueNormalTest() {
    String fullName = "Full Name";
    String mail = "abc@example.org";
    Map<String, String> fieldsCollection = new HashMap<String, String>();
    fieldsCollection.put(AdConnectionHelper.COMMON_NAME_ATTRIBUTE, fullName);
    fieldsCollection.put(AdConnectionHelper.MAIL_ATTRIBUTE, mail);
    Fields fields = getTestFields(fieldsCollection);

    assertThat(adConnectionHelper.getUserAttributeValue(fields, AdConnectionHelper.COMMON_NAME_ATTRIBUTE)).isEqualTo(fullName);

    assertThat(adConnectionHelper.getUserAttributeValue(fields, AdConnectionHelper.MAIL_ATTRIBUTE)).isEqualTo(mail);
  }

  private String getTestConnectionString(final String domainName) {
    return "GC://" + domainName + "/" + AdConnectionHelper.ROOT_DSE;
  }

  private Collection<String> getTestRequestedUserAttributes() {
    Collection<String> requestedAttributes = new ArrayList<String>();
    requestedAttributes.add(AdConnectionHelper.COMMON_NAME_ATTRIBUTE);
    requestedAttributes.add(AdConnectionHelper.MAIL_ATTRIBUTE);

    return requestedAttributes;
  }

  private _Recordset getTestRecordSet(boolean isEofSet, Map<String, String> fieldsCollection) {
    _Recordset recordSet = Mockito.mock(_Recordset.class);

    Mockito.when(recordSet.eof()).thenReturn(isEofSet);

    if (!isEofSet && fieldsCollection != null) {
      Fields fields = getTestFields(fieldsCollection);
      Mockito.when(recordSet.fields()).thenReturn(fields);
    }

    return recordSet;
  }

  private Fields getTestFields(final Map<String, String> fieldsCollection) {
    Fields fields = Mockito.mock(Fields.class);

    for (String fieldName : fieldsCollection.keySet()) {
      Field field = getTestField(fieldsCollection.get(fieldName));
      Mockito.when(fields.item(fieldName)).thenReturn(field);
    }

    return fields;
  }

  private Field getTestField(final String fieldValue) {
    Field field = Mockito.mock(Field.class);
    Mockito.when(field.value()).thenReturn(fieldValue);

    return field;
  }

  private void setupTestDefaultNamingContext(final String domainName, final String defaultNamingContext) {
    String testConnectionString = getTestConnectionString(domainName);
    IADs iads = Mockito.mock(IADs.class);
    Mockito.when(iads.get(AdConnectionHelper.DEFAULT_NAMING_CONTEXT_STR)).thenReturn(defaultNamingContext);
    Mockito.when(com4jWrapper.getObject(IADs.class, testConnectionString, null)).thenReturn(iads);
  }
}
