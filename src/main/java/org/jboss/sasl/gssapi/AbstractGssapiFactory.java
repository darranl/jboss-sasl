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

import org.jboss.sasl.util.AbstractSaslFactory;

/**
 * Common factory for the GSSAPI mechanism.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class AbstractGssapiFactory extends AbstractSaslFactory {

    /**
     * The name of the ANONYMOUS SASL mechanism.
     */
    public static final String GSSAPI = "GSSAPI";

    /**
     * Construct a new instance.
     */
    protected AbstractGssapiFactory() {
        super(GSSAPI);
    }

    @Override
    protected boolean isPassCredentials() {
        /*
         * Need to double check some details on this one but as a mechanism it should be possible to delegate the clients
         * credentials to the server.
         */

        return super.isPassCredentials();
    }

    @Override
    protected boolean isActiveSusceptible() {
        return false;
    }

    @Override
    protected boolean isPlainText() {
        return false;
    }

    @Override
    protected boolean isAnonymous() {
        return false;
    }

}
