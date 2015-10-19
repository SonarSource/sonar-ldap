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
package org.sonar.plugins.ldap.windows.auth.impl;

import com4j.COM4J;
import com4j.Com4jObject;
import com4j.Variant;
import com4j.typelibs.ado20.ClassFactory;
import com4j.typelibs.ado20._Command;
import com4j.typelibs.ado20._Connection;
import org.sonar.plugins.ldap.windows.auth.ICom4jWrapper;

public class Com4jWrapper implements ICom4jWrapper {

  @Override
  public _Command createCommand() {
    return ClassFactory.createCommand();
  }

  @Override
  public _Connection createConnection() {
    return ClassFactory.createConnection();
  }

  @Override
  public <T extends Com4jObject> T getObject(Class<T> primaryInterface, String fileName, String progId) {
    return COM4J.getObject(primaryInterface, fileName, progId);
  }

  @Override
  public Variant getMissing() {
    return Variant.getMissing();
  }

  @Override
  public void cleanUp() {
    COM4J.cleanUp();
  }
}
