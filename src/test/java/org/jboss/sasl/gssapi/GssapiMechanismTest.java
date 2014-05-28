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

import org.jboss.sasl.test.BaseTestCase;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Test case for testing GSSAPI authentication.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class GssapiMechanismTest extends BaseTestCase {

    private static TestKDC testKdc;

    @BeforeClass
    public static void startServers() {
        TestKDC testKdc = new TestKDC();
        testKdc.startDirectoryService();
        testKdc.startKDC();
        GssapiMechanismTest.testKdc = testKdc;
    }

    @AfterClass
    public static void stopServers() {
        if (testKdc != null) {
            testKdc.stopAll();
            testKdc = null;
        }
    }

    @Test
    public void helloWorld() {
        System.out.println("Hello World!!");
    }

}
