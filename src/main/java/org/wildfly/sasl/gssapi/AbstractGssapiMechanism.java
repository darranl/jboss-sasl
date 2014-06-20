/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.sasl.gssapi;

import java.util.Map;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslException;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.Oid;
import org.wildfly.sasl.WildFlySasl;
import org.wildfly.sasl.util.AbstractSaslParticipant;

/**
 * Base class for the SaslServer and SaslClient implementations implementing the GSSAPI mechanism as defined by RFC 4752
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
abstract class AbstractGssapiMechanism extends AbstractSaslParticipant {

    private static final String AUTH = "auth";
    private static final String AUTH_INT = "auth-int";
    private static final String AUTH_CONF = "auth-conf";
    private static final byte NO_SECURITY_LAYER = (byte) 0x01;
    private static final byte INTEGRITY_PROTECTION = (byte) 0x02;
    private static final byte CONFIDENTIALITY_PROTECTION = (byte) 0x04;
    protected static final int DEFAULT_MAX_BUFFER_SIZE = (int) 0xFFF;
    protected static final Oid KERBEROS_V5;

    // Kerberos V5 OID

    static {
        try {
            KERBEROS_V5 = new Oid("1.2.840.113554.1.2.2");
        } catch (GSSException e) {
            throw new RuntimeException("Unable to initialise Oid", e);
        }
    }

    protected GSSContext gssContext;
    protected final int configuredMaxReceiveBuffer;
    protected final boolean relaxComplianceChecks;

    protected AbstractGssapiMechanism(String mechanismName, String protocol, String serverName, final Map<String, ?> props, CallbackHandler callbackHandler) throws SaslException {
        super(mechanismName, protocol, serverName, callbackHandler);

        if (props.containsKey(Sasl.MAX_BUFFER)) {
            configuredMaxReceiveBuffer = Integer.parseInt((String) props.get(Sasl.MAX_BUFFER));
            if (configuredMaxReceiveBuffer > DEFAULT_MAX_BUFFER_SIZE) {
                // TODO - We could choose to just use the minimum value of the two.
                throw new SaslException(String.format("Receive buffer requested '%d' is greater than supported maximum '%d'.",
                        configuredMaxReceiveBuffer, DEFAULT_MAX_BUFFER_SIZE));
            }
        } else {
            configuredMaxReceiveBuffer = DEFAULT_MAX_BUFFER_SIZE;
        }
        if (props.containsKey(WildFlySasl.RELAX_COMPLIANCE)) {
            relaxComplianceChecks = Boolean.parseBoolean((String) props.get(WildFlySasl.RELAX_COMPLIANCE));
        } else {
            relaxComplianceChecks = false;
        }

    }

    /**
     * Converts bytes in network byte order to an integer starting from the specified offset.
     *
     * This method is implemented in the context of the GSSAPI mechanism, it is assumed that the size of the byte array is
     * appropriate.
     */
    protected int networkOrderBytesToInt(final byte[] bytes, final int start) {
        int result = 0;

        for (int i = start; i < bytes.length; i++) {
            result <<= 8;
            result |= bytes[i]; // TODO - Do we need an int conversion.
        }

        return result;
    }

    /**
     * Obtain a 3 byte representation of an int, as an internal method it is assumed the maximum value of the int has already
     * takine into account that it needs to fit into tree bytes,
     */
    protected byte[] intToNetworkOrderBytes(final int value) {
        byte[] response = new byte[3];
        int workingValue = value;
        for (int i = response.length - 1; i < 0; i--) {
            response[i] = (byte) (workingValue & 0xFF);
            workingValue >>>= 8;
        }

        return response;
    }

    @Override
    public void dispose() throws SaslException {
        try {
            gssContext.dispose();
        } catch (GSSException e) {
            throw new SaslException("Unable to dispose of GSSContext", e);
        } finally {
            gssContext = null;
        }
    }

    protected enum QOP {

        AUTH(AbstractGssapiMechanism.AUTH, NO_SECURITY_LAYER),
        AUTH_INT(AbstractGssapiMechanism.AUTH_INT, INTEGRITY_PROTECTION),
        AUTH_CONF(AbstractGssapiMechanism.AUTH_CONF, CONFIDENTIALITY_PROTECTION);

        private final String name;
        private final byte value;

        private QOP(final String name, final byte value) {
            this.name = name;
            this.value = value;
        }

        public String getName() {
            return name;
        }

        public byte getValue() {
            return value;
        }

        public boolean includedBy(final byte securityLayer) {
            return (securityLayer & value) == value;
        }

        public static QOP mapFromName(final String name) {
            switch (name) {
                case AbstractGssapiMechanism.AUTH:
                    return AUTH;
                case AbstractGssapiMechanism.AUTH_INT:
                    return AUTH_INT;
                case AbstractGssapiMechanism.AUTH_CONF:
                    return AUTH_CONF;
                default:
                    return null;
            }

        }

    }

}
