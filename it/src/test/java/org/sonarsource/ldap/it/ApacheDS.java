/*
 * SonarQube LDAP Plugin :: Integration Tests
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
package org.sonarsource.ldap.it;

import com.google.common.base.Preconditions;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import com.google.common.io.Closeables;
import org.apache.commons.io.FileUtils;
import org.apache.directory.server.core.CoreSession;
import org.apache.directory.server.core.DefaultDirectoryService;
import org.apache.directory.server.core.DirectoryService;
import org.apache.directory.server.core.entry.DefaultServerEntry;
import org.apache.directory.server.core.entry.ServerEntry;
import org.apache.directory.server.core.partition.impl.btree.jdbm.JdbmIndex;
import org.apache.directory.server.core.partition.impl.btree.jdbm.JdbmPartition;
import org.apache.directory.server.ldap.LdapServer;
import org.apache.directory.server.ldap.handlers.bind.MechanismHandler;
import org.apache.directory.server.ldap.handlers.bind.cramMD5.CramMd5MechanismHandler;
import org.apache.directory.server.ldap.handlers.bind.digestMD5.DigestMd5MechanismHandler;
import org.apache.directory.server.ldap.handlers.bind.gssapi.GssapiMechanismHandler;
import org.apache.directory.server.ldap.handlers.bind.plain.PlainMechanismHandler;
import org.apache.directory.server.protocol.shared.transport.TcpTransport;
import org.apache.directory.server.xdbm.Index;
import org.apache.directory.shared.ldap.constants.SupportedSaslMechanisms;
import org.apache.directory.shared.ldap.ldif.ChangeType;
import org.apache.directory.shared.ldap.ldif.LdifEntry;
import org.apache.directory.shared.ldap.ldif.LdifReader;
import org.apache.mina.util.AvailablePortFinder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.InputStream;
import java.util.Map;

/**
 * This class originally was developed in sonar-ldap-plugin and then was duplicated here with some modifications.
 */
public class ApacheDS {

  private static final Logger LOG = LoggerFactory.getLogger(ApacheDS.class);

  public static ApacheDS start(String baseDn, String workDir) throws Exception {
    return new ApacheDS(baseDn)
        .startDirectoryService(workDir)
        .startLdapServer();
  }

  public void stop() throws Exception {
    ldapServer.stop();
    directoryService.shutdown();
  }

  public String getUrl() {
    return "ldap://localhost:" + ldapServer.getPort();
  }

  /**
   * Stream will be closed automatically.
   */
  public void importLdif(InputStream is) throws Exception {
    Preconditions.checkState(directoryService.isStarted(), "Directory service not started");
    try {
      LdifReader entries = new LdifReader(is);
      CoreSession rootDSE = directoryService.getAdminSession();
      // see LdifFileLoader
      for (LdifEntry ldifEntry : entries) {
        LOG.info(ldifEntry.toString());
        if (ChangeType.Add == ldifEntry.getChangeType()) {
          rootDSE.add(new DefaultServerEntry(rootDSE.getDirectoryService().getRegistries(), ldifEntry.getEntry()));
        } else if (ChangeType.Modify == ldifEntry.getChangeType()) {
          rootDSE.modify(ldifEntry.getDn(), ldifEntry.getModificationItems());
        } else if (ChangeType.Delete == ldifEntry.getChangeType()) {
          rootDSE.delete(ldifEntry.getDn());
        }
      }
    } finally {
      Closeables.closeQuietly(is);
    }
  }

  public void disableAnonymousAccess() {
    directoryService.setAllowAnonymousAccess(false);
    ldapServer.setAllowAnonymousAccess(false);
  }

  public void enableAnonymousAccess() {
    directoryService.setAllowAnonymousAccess(true);
    ldapServer.setAllowAnonymousAccess(true);
  }

  private final String baseDn;
  private final DirectoryService directoryService;
  private final LdapServer ldapServer;

  private ApacheDS(String baseDn) {
    this.baseDn = baseDn;
    directoryService = new DefaultDirectoryService();
    ldapServer = new LdapServer();
  }

  private ApacheDS startDirectoryService(String workDirStr) throws Exception {
    Preconditions.checkState(!directoryService.isStarted());

    directoryService.setShutdownHookEnabled(false);

    File workDir = new File(workDirStr);
    FileUtils.deleteDirectory(workDir);
    directoryService.setWorkingDirectory(workDir);

    JdbmPartition partition = new JdbmPartition();
    partition.setId("test");
    partition.setSuffix(baseDn);
    partition.setIndexedAttributes(Sets.<Index<?, ServerEntry>> newHashSet(
        new JdbmIndex<String, ServerEntry>("ou"),
        new JdbmIndex<String, ServerEntry>("uid"),
        new JdbmIndex<String, ServerEntry>("dc"),
        new JdbmIndex<String, ServerEntry>("objectClass")));
    directoryService.setPartitions(Sets.newHashSet(partition));

    directoryService.startup();

    return this;
  }

  private ApacheDS startLdapServer() throws Exception {
    Preconditions.checkState(directoryService.isStarted());
    Preconditions.checkState(!ldapServer.isStarted());

    int port = AvailablePortFinder.getNextAvailable(1024);
    ldapServer.setTransports(new TcpTransport(port));
    ldapServer.setDirectoryService(directoryService);

    // Setup SASL mechanisms
    Map<String, MechanismHandler> mechanismHandlerMap = Maps.newHashMap();
    mechanismHandlerMap.put(SupportedSaslMechanisms.PLAIN, new PlainMechanismHandler());
    mechanismHandlerMap.put(SupportedSaslMechanisms.CRAM_MD5, new CramMd5MechanismHandler());
    mechanismHandlerMap.put(SupportedSaslMechanisms.DIGEST_MD5, new DigestMd5MechanismHandler());
    mechanismHandlerMap.put(SupportedSaslMechanisms.GSSAPI, new GssapiMechanismHandler());
    ldapServer.setSaslMechanismHandlers(mechanismHandlerMap);

    ldapServer.setSaslHost("localhost");
    // ldapServer.setSaslRealms(Collections.singletonList("example.org"));
    // TODO ldapServer.setSaslPrincipal();
    // The base DN containing users that can be SASL authenticated.
    ldapServer.setSearchBaseDn(baseDn);

    ldapServer.start();

    return this;
  }

}
