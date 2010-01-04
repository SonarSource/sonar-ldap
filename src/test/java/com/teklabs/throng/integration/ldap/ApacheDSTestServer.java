/*
 * Copyright (C) 2009
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.teklabs.throng.integration.ldap;

import org.apache.directory.server.core.entry.ServerEntry;
import org.apache.directory.server.core.interceptor.Interceptor;
import org.apache.directory.server.core.kerberos.KeyDerivationInterceptor;
import org.apache.directory.server.core.partition.Partition;
import org.apache.directory.server.core.partition.impl.btree.jdbm.JdbmIndex;
import org.apache.directory.server.core.partition.impl.btree.jdbm.JdbmPartition;
import org.apache.directory.server.kerberos.kdc.KdcServer;
import org.apache.directory.server.protocol.shared.transport.TcpTransport;
import org.apache.directory.server.protocol.shared.transport.UdpTransport;
import org.apache.directory.server.unit.AbstractServerTest;
import org.apache.directory.server.xdbm.Index;

import javax.naming.NamingException;
import javax.naming.directory.*;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Create and set up an LDAP test server which is used for tests.
 *
 * @author Evgeny Mandrikov
 */
public class ApacheDSTestServer extends AbstractTestServer {

    private InternalLdapServer wrappedService = new InternalLdapServer();

    private class InternalLdapServer extends AbstractServerTest {
        @Override
        public void setUp() throws Exception {
            super.setUp();
            ldapServer.setSaslPrincipal("ldap/localhost@" + getRealm());

            KdcServer kdcConfig = new KdcServer();
            kdcConfig.setDirectoryService(directoryService);
            kdcConfig.setTransports(new TcpTransport(6088), new UdpTransport(6088));
            kdcConfig.setEnabled(true);
            kdcConfig.setPrimaryRealm(getRealm());
            kdcConfig.setSearchBaseDn(getBaseDN());
            kdcConfig.setKdcPrincipal("krbtgt/" + getRealm() + "@" + getRealm());

            kdcConfig.start();

            // -------------------------------------------------------------------
            // Enable the krb5kdc schema
            // -------------------------------------------------------------------

            // check if krb5kdc is disabled
            Attributes krb5kdcAttrs = schemaRoot.getAttributes("cn=Krb5kdc");
            boolean isKrb5KdcDisabled = false;
            if (krb5kdcAttrs.get("m-disabled") != null) {
                isKrb5KdcDisabled = ((String) krb5kdcAttrs.get("m-disabled").get()).equalsIgnoreCase("TRUE");
            }

            // if krb5kdc is disabled then enable it
            if (isKrb5KdcDisabled) {
                Attribute disabled = new BasicAttribute("m-disabled");
                ModificationItem[] mods = new ModificationItem[]
                        {new ModificationItem(DirContext.REMOVE_ATTRIBUTE, disabled)};
                schemaRoot.modifyAttributes("cn=Krb5kdc", mods);
            }
        }

        @Override
        protected void configureLdapServer() {
            ldapServer.setAllowAnonymousAccess(true);
            ldapServer.setSaslHost("localhost");
            ldapServer.setSaslRealms(Collections.singletonList(getRealm()));
            // TODO ldapServer.setSaslPrincipal();
            // The base DN containing users that can be SASL authenticated.
            ldapServer.setSearchBaseDn(getBaseDN());
        }

        @Override
        public void tearDown() throws Exception {
            super.tearDown();
        }

        @Override
        public void importLdif(InputStream in) throws NamingException {
            try {
                super.importLdif(in);
            } finally {
                try {
                    in.close();
                } catch (IOException e) {
                    // TODO do nothing
                }
            }
        }

        @Override
        protected void configureDirectoryService() throws Exception {
            Set<Partition> partitions = new HashSet<Partition>();

            // Add partition
            JdbmPartition partition = new JdbmPartition();
            partition.setId(getId());
            partition.setSuffix(getBaseDN());

            // Add indices
            Set<Index<?, ServerEntry>> indexedAttrs = new HashSet<Index<?, ServerEntry>>();
            indexedAttrs.add(new JdbmIndex<String, ServerEntry>("ou"));
            indexedAttrs.add(new JdbmIndex<String, ServerEntry>("uid"));
            indexedAttrs.add(new JdbmIndex<String, ServerEntry>("dc"));
            indexedAttrs.add(new JdbmIndex<String, ServerEntry>("objectClass"));
            partition.setIndexedAttributes(indexedAttrs);

            partitions.add(partition);
            directoryService.setPartitions(partitions);

            // Create a working directory
            File workingDirectory = new File(getServerRoot());
            directoryService.setWorkingDirectory(workingDirectory);
            doDelete(directoryService.getWorkingDirectory());

            // For Krb5
            List<Interceptor> list = directoryService.getInterceptors();
            list.add(new KeyDerivationInterceptor());
            directoryService.setInterceptors(list);
        }
    }

    @Override
    public void start() throws Exception {
        wrappedService.setUp();
    }

    @Override
    public void stop() throws Exception {
        wrappedService.tearDown();
    }

    @Override
    public void initialize(String ldifFile) throws Exception {
        wrappedService.importLdif(getClass().getResourceAsStream(ldifFile));
    }
}
