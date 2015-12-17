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
package org.sonar.plugins.ldap.windows.auth;

import com.google.common.base.Preconditions;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import org.apache.commons.lang.StringUtils;
import org.mockito.Mockito;
import org.sonar.plugins.ldap.windows.stubs.HttpSessionStub;
import waffle.servlet.WindowsPrincipal;
import waffle.windows.auth.WindowsAccount;

public class WindowsAuthTestHelper {
  public static WindowsPrincipal getWindowsPrincipal(String userName, Collection<WindowsAccount> groups) {
    WindowsPrincipal windowsPrincipal = null;
    if (groups != null) {
      windowsPrincipal = Mockito.mock(WindowsPrincipal.class);
      Mockito.when(windowsPrincipal.getName()).thenReturn(userName);

      Map<String, WindowsAccount> groupsMap = new HashMap<>();
      for (WindowsAccount group : groups) {
        groupsMap.put(group.getFqn(), group);
      }
      Mockito.when(windowsPrincipal.getGroups()).thenReturn(groupsMap);
    }

    return windowsPrincipal;
  }

  public static HttpServletRequest getHttpServletRequest(String windowsPrincipalKey, Object windowsPrincipal) {
    Preconditions.checkArgument(StringUtils.isNotBlank(windowsPrincipalKey), "windowsPrincipalKey is null or empty");
    HttpServletRequest httpServletRequest = getHttpServletRequest();
    httpServletRequest.getSession().setAttribute(windowsPrincipalKey, windowsPrincipal);

    return httpServletRequest;
  }

  public static HttpServletRequest getHttpServletRequest() {
    HttpSession httpSession = new HttpSessionStub();
    HttpServletRequest httpServletRequest = Mockito.mock(HttpServletRequest.class);
    Mockito.when(httpServletRequest.getSession()).thenReturn(httpSession);

    return httpServletRequest;
  }
}
