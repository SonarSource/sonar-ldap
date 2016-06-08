/*
 * SonarQube LDAP Plugin :: Integration Tests
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
package org.sonarsource.ldap.it;

import com.google.common.base.Joiner;
import com.google.common.collect.Iterables;
import com.sonar.orchestrator.locator.FileLocation;
import com.sonar.orchestrator.locator.Location;
import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOCase;
import org.apache.commons.io.filefilter.IOFileFilter;
import org.apache.commons.io.filefilter.WildcardFileFilter;

import static java.lang.String.format;
import static org.apache.commons.io.filefilter.FileFilterUtils.and;
import static org.apache.commons.io.filefilter.FileFilterUtils.notFileFilter;

public abstract class AbstractTest {

  public static Location ldapPluginLocation() {
    return byWildcardMavenFilename(new File("../sonar-ldap-plugin/target/"), "sonar-ldap-plugin-*.jar");
  }

  /**
   * This method must be remove when the byWildcardMavenFilename method provided by Orchestrator will filter out javadoc jar
   */
  private static FileLocation byWildcardMavenFilename(File directory, String wildcardFilename) {
    if (!directory.exists()) {
      throw new IllegalStateException(format("Directory [%s] does not exist", directory));
    }
    IOFileFilter artifactFilter = new WildcardFileFilter(wildcardFilename, IOCase.SENSITIVE);
    IOFileFilter sourcesFilter = notFileFilter(new WildcardFileFilter("*-sources.jar"));
    IOFileFilter testsFilter = notFileFilter(new WildcardFileFilter("*-tests.jar"));
    IOFileFilter javadocFilter = notFileFilter(new WildcardFileFilter("*-javadoc.jar"));
    IOFileFilter filters = and(artifactFilter, sourcesFilter, testsFilter, javadocFilter);
    Collection<File> files = new ArrayList<>(FileUtils.listFiles(directory, filters, null));
    return getOnlyFile(directory, wildcardFilename, files);
  }


  private static FileLocation getOnlyFile(File directory, String wildcardFilename, Collection<File> files) {
    if (files.isEmpty()) {
      throw new IllegalStateException(format("No files match [%s] in directory [%s]", wildcardFilename, directory));
    }
    if (files.size() > 1) {
      throw new IllegalStateException(format("Multiple files match [%s] in directory [%s]: %s", wildcardFilename, directory, Joiner.on(", ").join(files)));
    }
    return FileLocation.of(Iterables.getOnlyElement(files));
  }

}
