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
package org.sonar.plugins.ldap.windows;

import com.sun.jna.platform.win32.Win32Exception;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.sonar.api.config.Settings;
import org.sonar.api.security.UserDetails;
import org.sonar.plugins.ldap.windows.auth.WindowsAuthSettings;
import org.sonar.plugins.ldap.windows.auth.WindowsAuthTestHelper;
import org.sonar.plugins.ldap.windows.stubs.HttpSessionStub;
import waffle.servlet.WindowsPrincipal;
import waffle.windows.auth.IWindowsAccount;
import waffle.windows.auth.IWindowsAuthProvider;
import waffle.windows.auth.IWindowsIdentity;
import waffle.windows.auth.WindowsAccount;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

public class WindowsAuthenticationHelperTest {
  private WindowsAuthenticationHelper authenticationHelper;
  private IWindowsAuthProvider windowsAuthProvider;
  private AdConnectionHelper adConnectionHelper;
  private WindowsAuthSettings windowsAuthSettings;

  @Before
  public void initialize() {
    windowsAuthProvider = mock(IWindowsAuthProvider.class);
    adConnectionHelper = mock(AdConnectionHelper.class);
    windowsAuthSettings = new WindowsAuthSettings(new Settings());

    authenticationHelper = new WindowsAuthenticationHelper(windowsAuthSettings, windowsAuthProvider, adConnectionHelper);
  }

  @Test(expected = NullPointerException.class)
  public void isUserAuthenticatedNullArgCheck() {
    authenticationHelper.isUserSsoAuthenticated(null);
  }

  @Test
  public void isUserAuthenticatedNullHttpSessionTest() {
    HttpServletRequest servletRequest = mock(HttpServletRequest.class);
    assertThat(authenticationHelper.isUserSsoAuthenticated(servletRequest)).isFalse();
  }

  @Test
  public void isUserSsoAuthenticatedTests() {
    runIsUserSsoAuthenticated(null, false);
    runIsUserSsoAuthenticated(new Object(), false);
    runIsUserSsoAuthenticated(mock(WindowsPrincipal.class), true);
  }

  @Test(expected = NullPointerException.class)
  public void getWindowsPrincipalHttpServletRequestNullArgCheck() {
    authenticationHelper.getWindowsPrincipal(null, WindowsAuthenticationHelper.SSO_PRINCIPAL_KEY);
  }

  @Test(expected = NullPointerException.class)
  public void getWindowsPrincipalWindowsPrincipalNullArgCheck() {
    authenticationHelper.getWindowsPrincipal(mock(HttpServletRequest.class), null);
  }

  @Test(expected = NullPointerException.class)
  public void getWindowsPrincipalWindowsPrincipalEmptyArgCheck() {
    authenticationHelper.getWindowsPrincipal(mock(HttpServletRequest.class), null);
  }

  @Test
  public void getWindowsPrincipalNullHttpSessionTest() {
    HttpServletRequest servletRequest = mock(HttpServletRequest.class);
    assertThat(authenticationHelper.getWindowsPrincipal(servletRequest, WindowsAuthenticationHelper.SSO_PRINCIPAL_KEY)).isNull();
    assertThat(authenticationHelper.getWindowsPrincipal(servletRequest, WindowsAuthenticationHelper.BASIC_AUTH_PRINCIPAL_KEY)).isNull();
  }

  @Test
  public void getWindowsPrincipalTests() {
    runGetWindowsPrincipal(WindowsAuthenticationHelper.SSO_PRINCIPAL_KEY, null, null);
    runGetWindowsPrincipal(WindowsAuthenticationHelper.BASIC_AUTH_PRINCIPAL_KEY, null, null);

    runGetWindowsPrincipal(WindowsAuthenticationHelper.SSO_PRINCIPAL_KEY, new Object(), null);
    runGetWindowsPrincipal(WindowsAuthenticationHelper.BASIC_AUTH_PRINCIPAL_KEY, new Object(), null);

    WindowsPrincipal windowsPrincipal = mock(WindowsPrincipal.class);
    runGetWindowsPrincipal(WindowsAuthenticationHelper.SSO_PRINCIPAL_KEY, windowsPrincipal, windowsPrincipal);
    runGetWindowsPrincipal(WindowsAuthenticationHelper.BASIC_AUTH_PRINCIPAL_KEY, windowsPrincipal, windowsPrincipal);
  }

  @Test(expected = NullPointerException.class)
  public void setWindowsPrincipalNullHttpServletRequestCheck() {
    authenticationHelper.setWindowsPrincipalForBasicAuth(null, mock(WindowsPrincipal.class));
  }

  @Test(expected = NullPointerException.class)
  public void setWindowsPrincipalNullWindowsPrincipalCheck() {
    authenticationHelper.setWindowsPrincipalForBasicAuth(mock(HttpServletRequest.class), null);
  }

  @Test
  public void setWindowsPrincipalTests() {
    WindowsPrincipal windowsPrincipal = mock(WindowsPrincipal.class);
    HttpSession httpSession = new HttpSessionStub();

    HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
    Mockito.when(httpServletRequest.getSession()).thenReturn(httpSession);

    authenticationHelper.setWindowsPrincipalForBasicAuth(httpServletRequest, windowsPrincipal);

    assertThat(httpSession.getAttribute(WindowsAuthenticationHelper.BASIC_AUTH_PRINCIPAL_KEY)).isEqualTo(windowsPrincipal);
  }

  @Test(expected = NullPointerException.class)
  public void removeWindowsPrincipalForBasicAuthNullArgCheck() {
    authenticationHelper.removeWindowsPrincipalForBasicAuth(null);
  }

  @Test
  public void removeWindowsPrincipalForBasicAuthTests() {
    runRemoveWindowsPrincipalForBasicAuth(true);
    runRemoveWindowsPrincipalForBasicAuth(false);
  }

  @Test(expected = NullPointerException.class)
  public void removeWindowsPrincipalForSsoNullArgCheck() {
    authenticationHelper.removeWindowsPrincipalForSso(null);
  }

  @Test
  public void removeWindowsPrincipalForSsoTests() {
    runRemoveWindowsPrincipalForSsoTests(true);
    runRemoveWindowsPrincipalForSsoTests(false);
  }

  @Test(expected = IllegalArgumentException.class)
  public void logonUserNullCheckUserName() {
    authenticationHelper.logonUser(null, "secret");
  }

  @Test(expected = IllegalArgumentException.class)
  public void logonUserNullCheckPassword() {
    authenticationHelper.logonUser("user", null);
  }

  @Test
  public void logonUserTests() {
    runLogonUserTest("DOMAIN\\User", "secret", true);
    runLogonUserTest("DOMAIN\\User", "invalid-secret", false);
  }

  @Test(expected = NullPointerException.class)
  public void getUserDetailsFromHttpServletRequestNullCheck() {
    authenticationHelper.getSsoUserDetails((HttpServletRequest) null);
  }

  @Test
  public void getUserDetailsFromHttpServletRequestWindowsPrincipalNull() {
    HttpServletRequest httpServletRequest = WindowsAuthTestHelper.getHttpServletRequest(WindowsAuthenticationHelper.SSO_PRINCIPAL_KEY, null);
    assertThat(authenticationHelper.getSsoUserDetails(httpServletRequest)).isNull();
  }

  @Test
  public void getUserDetailsFromHttpServletRequestTests() {
    String userName = "User";
    String domainName = "Domain";

    UserDetails expectedUserDetails = new UserDetails();
    expectedUserDetails.setUserId("User@Domain");
    expectedUserDetails.setName("Full Name");
    expectedUserDetails.setEmail("abc@example.org");

    runGetUserDetailsFromHttpServletRequestTest(domainName, userName, true, expectedUserDetails);
    runGetUserDetailsFromHttpServletRequestTest(domainName, userName, false, null);
  }

  @Test(expected = IllegalArgumentException.class)
  public void getUserDetailsFromUserNameNullCheck() {
    authenticationHelper.getUserDetails((String) null);
  }

  @Test(expected = IllegalArgumentException.class)
  public void getUserDetailsFromUserNameEmptyCheck() {
    authenticationHelper.getUserDetails("");
  }

  @Test
  public void getUserDetailsFromUserNameWindowsAccountNullTest() {
    String userName = "User";
    String domainName = "Domain";
    String userNameWithDomain = getAccountNameWithDomain(domainName, "\\", userName);

    Win32Exception win32Exception = mock(Win32Exception.class);
    IWindowsAccount windowsAccount = getIWindowsAccount(domainName, userName);

    assertThat(authenticationHelper.getUserDetails(userNameWithDomain)).isNull();

    Mockito.when(windowsAuthProvider.lookupAccount(userNameWithDomain)).thenThrow(win32Exception);
    assertThat(authenticationHelper.getUserDetails(userNameWithDomain)).isNull();
    Mockito.verify(win32Exception, Mockito.times(1)).getMessage();
  }

  @Test
  public void getUserDetailsFromUserNameTests() {
    String userName = "User";
    String domainName = "Domain";

    UserDetails expectedUserDetails = new UserDetails();
    expectedUserDetails.setUserId("User@Domain");
    expectedUserDetails.setName("Full Name");
    expectedUserDetails.setEmail("abc@example.org");

    runGetUserDetailsFromUserNameTest(domainName, userName, true, expectedUserDetails);
    runGetUserDetailsFromUserNameTest(domainName, userName, false, null);
  }

  @Test
  public void getUserDetailsWindowsAccountDifferentUserIdFormatTests() {
    String domainName = "DOMAIN";
    String user = "User";
    String userName = "User Name";
    String mail = "User@example.org";

    IWindowsAccount windowsAccount = getIWindowsAccount(domainName, user);

    UserDetails expectedUserDetailsUln = getExpectedUserDetails(user, userName, mail);
    UserDetails expectedUserDetailsUlnDownCase = getExpectedUserDetails(user.toLowerCase(), userName, mail);

    UserDetails expectedUserDetailsUpn = getExpectedUserDetails(user + "@" + domainName, userName, mail);
    UserDetails expectedUserDetailsUpnDownCase = getExpectedUserDetails(
      getAccountNameWithDomain(user, "@", domainName).toLowerCase(), userName, mail);

    runGetUserDetailsFromWindowsAccountTest(windowsAccount, true, false, expectedUserDetailsUln);
    runGetUserDetailsFromWindowsAccountTest(windowsAccount, true, true, expectedUserDetailsUlnDownCase);

    runGetUserDetailsFromWindowsAccountTest(windowsAccount, false, false, expectedUserDetailsUpn);
    runGetUserDetailsFromWindowsAccountTest(windowsAccount, false, true, expectedUserDetailsUpnDownCase);
  }

  @Test(expected = NullPointerException.class)
  public void getUserGroupsNullArgumentCheck() {
    authenticationHelper.getUserGroups(null);
  }

  @Test
  public void getUserGroupsTestCompatibilityModeDisabledGroupNames() {
    String domainName = "Domain";
    String groupName = "Group1";

    Collection<WindowsAccount> groups = new ArrayList<>();
    WindowsAccount windowsAccount = getWindowsAccount(domainName, groupName);
    groups.add(windowsAccount);

    Collection<String> expectedGroups = new ArrayList<>();
    expectedGroups.add(groupName + "@" + domainName);

    Collection<String> expectedGroupsDownCase = new ArrayList<>();
    expectedGroupsDownCase.add(groupName.toLowerCase() + "@" + domainName.toLowerCase());

    this.runGetUserGroupsTest(domainName, "user", groups, false, false, null, expectedGroups);
    this.runGetUserGroupsTest(domainName, "user", groups, false, true, null, expectedGroupsDownCase);
  }

  @Test
  public void getUserGroupsTestCompatibilityModeEnabledGroupNames() {
    String domainNameA = "DomainA";
    String domainNameB = "DomainB";
    String groupName = "Group1";

    Collection<WindowsAccount> groups = new ArrayList<>();
    groups.add(getWindowsAccount(domainNameA, groupName));
    groups.add(getWindowsAccount(domainNameB, groupName));

    Collection<String> expectedGroups = new ArrayList<>();
    expectedGroups.add(groupName);

    runGetUserGroupsTest(domainNameA, "user", groups, true, false, "cn", expectedGroups);
    runGetUserGroupsTest(domainNameA, "user", groups, true, true, "sAMAccountName", expectedGroups);
  }

  private void runIsUserSsoAuthenticated(Object windowsPrincipal, boolean expIsUserAuthenticated) {
    HttpServletRequest servletRequest = WindowsAuthTestHelper.getHttpServletRequest(WindowsAuthenticationHelper.SSO_PRINCIPAL_KEY, windowsPrincipal);
    assertThat(authenticationHelper.isUserSsoAuthenticated(servletRequest)).isEqualTo(expIsUserAuthenticated);
  }

  private void runGetWindowsPrincipal(String windowsPrincipalAttributeKey, Object windowsPrincipalAttributeValue, WindowsPrincipal expectedWindowsPrincipal) {
    HttpServletRequest servletRequest = WindowsAuthTestHelper.getHttpServletRequest(windowsPrincipalAttributeKey, windowsPrincipalAttributeValue);
    assertThat(authenticationHelper.getWindowsPrincipal(servletRequest, windowsPrincipalAttributeKey)).isEqualTo(expectedWindowsPrincipal);
  }

  private void runRemoveWindowsPrincipalForBasicAuth(boolean isAttributePresent) {
    HttpSession httpSession = new HttpSessionStub();
    if (isAttributePresent) {
      httpSession.setAttribute(WindowsAuthenticationHelper.BASIC_AUTH_PRINCIPAL_KEY, mock(WindowsPrincipal.class));
    }

    HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
    Mockito.when(httpServletRequest.getSession()).thenReturn(httpSession);

    authenticationHelper.removeWindowsPrincipalForBasicAuth(httpServletRequest);

    assertThat(httpSession.getAttribute(WindowsAuthenticationHelper.BASIC_AUTH_PRINCIPAL_KEY)).isNull();
  }

  private void runRemoveWindowsPrincipalForSsoTests(boolean isAttributePresent) {
    HttpSession httpSession = new HttpSessionStub();
    if (isAttributePresent) {
      httpSession.setAttribute(WindowsAuthenticationHelper.SSO_PRINCIPAL_KEY, mock(WindowsPrincipal.class));
    }

    HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
    Mockito.when(httpServletRequest.getSession()).thenReturn(httpSession);

    authenticationHelper.removeWindowsPrincipalForSso(httpServletRequest);

    assertThat(httpSession.getAttribute(WindowsAuthenticationHelper.SSO_PRINCIPAL_KEY)).isNull();
  }

  private void runLogonUserTest(String userName, String password, boolean isLogonUserSuccessful) {
    IWindowsIdentity windowsIdentity = null;
    Win32Exception win32Exception = mock(Win32Exception.class);

    if (isLogonUserSuccessful) {
      windowsIdentity = mock(IWindowsIdentity.class);
      Mockito.when(windowsIdentity.getFqn()).thenReturn(userName);
      Mockito.when(windowsIdentity.getGroups()).thenReturn(new IWindowsAccount[0]);
      Mockito.when(windowsAuthProvider.logonUser(userName, password)).thenReturn(windowsIdentity);
    } else {
      Mockito.when(windowsAuthProvider.logonUser(userName, password)).thenThrow(win32Exception);
    }

    WindowsPrincipal windowsPrincipal = authenticationHelper.logonUser(userName, password);

    if (isLogonUserSuccessful) {
      assertThat(windowsPrincipal.getName()).isEqualTo(windowsIdentity.getFqn());
      Mockito.verify(windowsIdentity, Mockito.times(1)).dispose();
      Mockito.verify(win32Exception, Mockito.times(0)).getMessage();
    } else {
      assertThat(windowsPrincipal).isNull();
      Mockito.verify(win32Exception, Mockito.times(1)).getMessage();
    }
    Mockito.verify(windowsAuthProvider, Mockito.times(1)).logonUser(userName, password);
  }

  private static void runGetUserDetailsFromUserNameTest(String domainName, String userName, boolean doesUserExist,
    UserDetails expectedUserDetails) {
    String userNameWithDomain = getAccountNameWithDomain(domainName, "\\", userName);
    WindowsAuthenticationHelper authenticationHelper = getWindowsAuthHelperForGetUserDetailsTest(domainName, userName,
      doesUserExist, expectedUserDetails);

    UserDetails userDetails = authenticationHelper.getUserDetails(userNameWithDomain);

    if (expectedUserDetails == null) {
      assertThat(userDetails).isNull();
    } else {
      assertThat(userDetails).isNotNull();
      assertThat(userDetails).isEqualToComparingFieldByField(expectedUserDetails);
    }
  }

  private static void runGetUserDetailsFromHttpServletRequestTest(String domainName, String userName, boolean doesUserExist,
    UserDetails expectedUserDetails) {
    String userNameWithDomain = getAccountNameWithDomain(domainName, "\\", userName);
    WindowsAuthenticationHelper authenticationHelper = getWindowsAuthHelperForGetUserDetailsTest(domainName, userName,
      doesUserExist, expectedUserDetails);
    WindowsPrincipal windowsPrincipal = mock(WindowsPrincipal.class);
    Mockito.when(windowsPrincipal.getName()).thenReturn(userNameWithDomain);
    HttpServletRequest servletRequest = WindowsAuthTestHelper.getHttpServletRequest(WindowsAuthenticationHelper.SSO_PRINCIPAL_KEY, windowsPrincipal);

    UserDetails userDetails = authenticationHelper.getSsoUserDetails(servletRequest);

    if (expectedUserDetails == null) {
      assertThat(userDetails).isNull();
    } else {
      assertThat(userDetails).isNotNull();
      assertThat(userDetails).isEqualToComparingFieldByField(expectedUserDetails);
    }
  }

  private static WindowsAuthenticationHelper getWindowsAuthHelperForGetUserDetailsTest(String domainName, String userName,
    boolean doesUserExist, UserDetails expectedUserDetails) {
    IWindowsAuthProvider windowsAuthProvider = mock(IWindowsAuthProvider.class);
    WindowsAuthSettings windowsAuthSettings = new WindowsAuthSettings(new Settings());
    AdConnectionHelper adConnectionHelper = mock(AdConnectionHelper.class);
    String userNameWithDomain = getAccountNameWithDomain(domainName, "\\", userName);
    if (doesUserExist) {
      IWindowsAccount windowsAccount = mock(IWindowsAccount.class);
      Mockito.when(windowsAccount.getDomain()).thenReturn(domainName);
      Mockito.when(windowsAccount.getName()).thenReturn(userName);

      Mockito.when(windowsAuthProvider.lookupAccount(userNameWithDomain)).thenReturn(windowsAccount);
    }

    Map<String, String> attributesUserDetails = null;
    if (expectedUserDetails != null) {
      attributesUserDetails = new HashMap<>();
      attributesUserDetails.put(windowsAuthSettings.getLdapUserRealNameAttribute(), expectedUserDetails.getName());
      attributesUserDetails.put(AdConnectionHelper.MAIL_ATTRIBUTE, expectedUserDetails.getEmail());
    }

    Collection<String> attributeNames = new ArrayList<>();
    attributeNames.add(windowsAuthSettings.getLdapUserRealNameAttribute());
    attributeNames.add(AdConnectionHelper.MAIL_ATTRIBUTE);
    Mockito.when(adConnectionHelper.getUserDetails(domainName, userName, attributeNames)).thenReturn(attributesUserDetails);

    return new WindowsAuthenticationHelper(new WindowsAuthSettings(new Settings()), windowsAuthProvider,
      adConnectionHelper);
  }

  private void runGetUserDetailsFromWindowsAccountTest(IWindowsAccount windowsAccount, boolean isCompatibilityModeEnabled,
    boolean isAuthenticatorDownCase, UserDetails expectedUserDetails) {
    windowsAuthSettings = new WindowsAuthSettings(new Settings()
      .setProperty(WindowsAuthSettings.LDAP_WINDOWS_COMPATIBILITY_MODE, Boolean.toString(isCompatibilityModeEnabled))
      .setProperty(WindowsAuthSettings.SONAR_AUTHENTICATOR_LOGIN_DOWNCASE, Boolean.toString(isAuthenticatorDownCase)));

    Map<String, String> attributesUserDetails = null;
    if (expectedUserDetails != null) {
      attributesUserDetails = new HashMap<String, String>();
      attributesUserDetails.put(windowsAuthSettings.getLdapUserRealNameAttribute(), expectedUserDetails.getName());
      attributesUserDetails.put(AdConnectionHelper.MAIL_ATTRIBUTE, expectedUserDetails.getEmail());
    }

    Collection<String> attributeNames = new ArrayList<>();
    attributeNames.add(windowsAuthSettings.getLdapUserRealNameAttribute());
    attributeNames.add(AdConnectionHelper.MAIL_ATTRIBUTE);
    Mockito.when(adConnectionHelper.getUserDetails(windowsAccount.getDomain(), windowsAccount.getName(), attributeNames)).thenReturn(attributesUserDetails);

    authenticationHelper = new WindowsAuthenticationHelper(windowsAuthSettings, windowsAuthProvider, adConnectionHelper);

    assertThat(authenticationHelper.getUserDetails(windowsAccount)).isEqualToComparingFieldByField(expectedUserDetails);
  }

  private void runGetUserGroupsTest(String domainName, String userName, Collection<WindowsAccount> windowsAccounts,
    boolean isCompatibilityModeEnabled, boolean isGroupsDownCase, String groupIdAttribute, Collection<String> expectedGroups) {
    String userNameWithDomain = getAccountNameWithDomain(domainName, "\\", userName);

    windowsAuthSettings = new WindowsAuthSettings(new Settings()
      .setProperty(WindowsAuthSettings.LDAP_WINDOWS_COMPATIBILITY_MODE, Boolean.toString(isCompatibilityModeEnabled))
      .setProperty(WindowsAuthSettings.LDAP_GROUP_ID_ATTRIBUTE, groupIdAttribute)
      .setProperty(WindowsAuthSettings.LDAP_WINDOWS_GROUP_DOWNCASE, Boolean.toString(isGroupsDownCase)));

    windowsAuthProvider = mock(IWindowsAuthProvider.class);
    adConnectionHelper = mock(AdConnectionHelper.class);

    if (isCompatibilityModeEnabled) {
      IWindowsAccount windowsAccount = getIWindowsAccount(domainName, userName);
      Mockito.when(windowsAuthProvider.lookupAccount(userNameWithDomain)).thenReturn(windowsAccount);
      Mockito.when(adConnectionHelper.getUserGroupsInDomain(domainName, userName, groupIdAttribute)).thenReturn(expectedGroups);
    }

    authenticationHelper = new WindowsAuthenticationHelper(windowsAuthSettings, windowsAuthProvider, adConnectionHelper);

    WindowsPrincipal windowsPrincipal = WindowsAuthTestHelper.getWindowsPrincipal(userNameWithDomain, windowsAccounts);

    Collection groups = authenticationHelper.getUserGroups(windowsPrincipal);
    if (expectedGroups == null) {
      assertThat(groups).isNull();
    } else {
      assertThat(groups).hasSameElementsAs(expectedGroups);
    }

    if (isCompatibilityModeEnabled) {
      Mockito.verify(windowsAuthProvider, Mockito.times(1)).lookupAccount(userNameWithDomain);
      Mockito.verify(adConnectionHelper, Mockito.times(1)).getUserGroupsInDomain(domainName, userName, groupIdAttribute);
    } else {
      Mockito.verify(windowsAuthProvider, Mockito.times(0)).lookupAccount(userNameWithDomain);
      Mockito.verify(adConnectionHelper, Mockito.times(0)).getUserGroupsInDomain(domainName, userName, groupIdAttribute);
    }
  }

  private static UserDetails getExpectedUserDetails(String userId, String userName, String mail) {
    UserDetails userDetails = new UserDetails();
    userDetails.setUserId(userId);
    userDetails.setName(userName);
    userDetails.setEmail(mail);

    return userDetails;
  }

  private static WindowsAccount getWindowsAccount(String domainName, String accountName) {
    WindowsAccount windowsAccount = mock(WindowsAccount.class);
    Mockito.when(windowsAccount.getFqn()).thenReturn(domainName + "\\" + accountName);
    Mockito.when(windowsAccount.getName()).thenReturn(accountName);
    Mockito.when(windowsAccount.getDomain()).thenReturn(domainName);

    return windowsAccount;
  }

  private static IWindowsAccount getIWindowsAccount(String domainName, String accountName) {
    IWindowsAccount windowsAccount = mock(IWindowsAccount.class);
    Mockito.when(windowsAccount.getFqn()).thenReturn(domainName + "\\" + accountName);
    Mockito.when(windowsAccount.getName()).thenReturn(accountName);
    Mockito.when(windowsAccount.getDomain()).thenReturn(domainName);

    return windowsAccount;
  }

  private static String getAccountNameWithDomain(final String domainName, final String separator, final String accountName) {
    String accountNameWithDomain = "";
    if (domainName != null) {
      accountNameWithDomain = domainName;
    }
    if (separator != null) {
      accountNameWithDomain += separator;
    }
    if (accountName != null) {
      accountNameWithDomain += accountName;
    }

    return accountNameWithDomain;
  }

}
