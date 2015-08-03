package org.sonarsource.ldap.it;

import com.sonar.orchestrator.locator.FileLocation;
import com.sonar.orchestrator.locator.Location;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;
import org.sonar.updatecenter.common.Version;

public abstract class AbstractTest {

  private static Version artifactVersion;

  // TODO the way to retrieve current plugin jar should be coded in orchestrator
  public static Location ldapPluginLocation() {
    return FileLocation.of("../target/sonar-ldap-plugin-" + artifactVersion() + ".jar");
  }

  private static Version artifactVersion() {
    if (artifactVersion == null) {
      try (FileInputStream fis = new FileInputStream(new File("../target/maven-archiver/pom.properties"))) {
        Properties props = new Properties();
        props.load(fis);
        artifactVersion = Version.create(props.getProperty("version"));
        return artifactVersion;
      } catch (IOException e) {
        throw new IllegalStateException(e);
      }
    }
    return artifactVersion;
  }

}
