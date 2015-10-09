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
package org.sonar.plugins.ldap.windows.auth;

import com4j.Com4jObject;
import com4j.Variant;
import com4j.typelibs.ado20._Command;
import com4j.typelibs.ado20._Connection;

/* A Com4J api wrapper*/
public interface ICom4jWrapper {

  _Command createCommand();

  _Connection createConnection();

  <T extends Com4jObject> T getObject(Class<T> primaryInterface, String fileName, String progId);

  Variant getMissing();

  void cleanUp();
}
