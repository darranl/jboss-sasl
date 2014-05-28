/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.jboss.sasl.gssapi;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;

import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.ldif.LdifEntry;
import org.apache.directory.api.ldap.model.ldif.LdifReader;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.server.core.api.CoreSession;
import org.apache.directory.server.core.api.DirectoryService;
import org.apache.directory.server.core.api.partition.Partition;
import org.apache.directory.server.core.factory.DefaultDirectoryServiceFactory;
import org.apache.directory.server.core.factory.DirectoryServiceFactory;
import org.apache.directory.server.core.factory.PartitionFactory;
import org.apache.directory.server.kerberos.KerberosConfig;
import org.apache.directory.server.kerberos.kdc.KdcServer;
import org.apache.directory.server.protocol.shared.transport.UdpTransport;

/**
 * Utility class to wrap starting and stopping of the directory server and the KDC.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class TestKDC {

    private File workingDir;
    private DirectoryService directoryService;
    private KdcServer kdcServer;
    private String originalConfig;

    public void startDirectoryService() {
        if (directoryService != null) {
            throw new IllegalStateException("DirectoryService already started");
        }
        createWorkingDir();

        try {
            DirectoryServiceFactory dsf = new DefaultDirectoryServiceFactory();
            DirectoryService ds = dsf.getDirectoryService();

            dsf.init("Test Service");

            ds.getChangeLog().setEnabled(false);

            SchemaManager schemaManager = ds.getSchemaManager();
            createPartition(dsf, schemaManager, "jboss", "dc=jboss,dc=org", ds, workingDir, "uid", "krb5PrincipalName");

            CoreSession adminSession = ds.getAdminSession();
            processLdif(schemaManager, adminSession, "/KerberosTesting.ldif");

            // Only using the DirectoryService to back the KDC so don't expose a LDAP server.

            directoryService = ds;
        } catch (Exception e) {
            throw new IllegalStateException("Unable to initialise DirectoryService", e);
        }
    }

    private static void createPartition(final DirectoryServiceFactory dsf, final SchemaManager schemaManager, final String id,
            final String suffix, final DirectoryService directoryService, final File workingDir,
            final String... indexAttributes) throws Exception {
        PartitionFactory pf = dsf.getPartitionFactory();
        Partition p = pf.createPartition(schemaManager, directoryService.getDnFactory(), id, suffix, 1000, workingDir);
        for (String current : indexAttributes) {
            pf.addIndex(p, current, 10);
        }
        p.initialize();
        directoryService.addPartition(p);
    }

    private static void processLdif(final SchemaManager schemaManager, final CoreSession adminSession, final String ldifName)
            throws LdapException, IOException {
        InputStream ldifInput = TestKDC.class.getResourceAsStream(ldifName);
        LdifReader ldifReader = new LdifReader(ldifInput);
        for (LdifEntry ldifEntry : ldifReader) {
            adminSession.add(new DefaultEntry(schemaManager, ldifEntry.getEntry()));
        }
        ldifReader.close();
        ldifInput.close();
    }

    private void stopDirectoryService() {
        if (directoryService == null) {
            return;
        }

        try {
            directoryService.shutdown();
            directoryService = null;
        } catch (Exception e) {
            throw new IllegalStateException("Error shutting down directory service", e);
        }
    }

    public void startKDC() {
        if (directoryService == null) {
            throw new IllegalStateException("No DirectoryService Available for KDC");
        }
        if (kdcServer != null) {
            throw new IllegalStateException("KDCServer already started");
        }

        final URL configPath = TestKDC.class.getResource("/krb5.conf");
        originalConfig = System.setProperty("java.security.krb5.conf", configPath.getFile());

        KdcServer kdcServer = new KdcServer();
        kdcServer.setServiceName("TestKDCServer");
        kdcServer.setSearchBaseDn("dc=jboss,dc=org");
        KerberosConfig config = kdcServer.getConfig();
        config.setServicePrincipal("krbtgt/JBOSS.ORG@JBOSS.ORG");
        config.setPrimaryRealm("JBOSS.ORG");
        config.setMaximumTicketLifetime(60000 * 1440);
        config.setMaximumRenewableLifetime(60000 * 10080);

        config.setPaEncTimestampRequired(false);

        UdpTransport udp = new UdpTransport("localhost", 6088);
        kdcServer.addTransports(udp);

        kdcServer.setDirectoryService(directoryService);

        // Launch the server
        try {
            kdcServer.start();
            this.kdcServer = kdcServer;
        } catch (IOException | LdapInvalidDnException e) {
            throw new IllegalStateException("Unable to start KDC", e);
        }
    }

    private void stopKDC() {
        if (kdcServer == null) {
            return;
        }

        kdcServer.stop();
        kdcServer = null;

        if (originalConfig != null) {
            System.setProperty("java.security.krb5.conf", originalConfig);
        }
    }

    private void createWorkingDir() {
        workingDir = new File("./target/apache-ds/working");
        if (workingDir.exists() == false) {
            if (workingDir.mkdirs() == false) {
                throw new IllegalStateException("Unable to create working dir.");
            }
        }
        emptyDir(workingDir);
    }

    private void cleanWorkingDir() {
        emptyDir(workingDir);
        workingDir = null;
    }

    private void emptyDir(final File dir) {
        for (File current : dir.listFiles()) {
            if (current.delete() == false) {
                try {
                    throw new IllegalStateException(String.format("Unable to delete file '%s' from working dir '%s'.",
                            current.getName(), workingDir.getCanonicalPath()));
                } catch (IOException e) {
                    throw new IllegalStateException(e);
                }
            }
        }
    }

    public void stopAll() {
        stopKDC();
        stopDirectoryService();
        cleanWorkingDir();
    }

}
