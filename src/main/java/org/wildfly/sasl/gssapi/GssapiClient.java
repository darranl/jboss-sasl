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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Map;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslException;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.MessageProp;
import org.ietf.jgss.Oid;
import org.wildfly.sasl.WildFlySasl;
import org.wildfly.sasl.util.AbstractSaslClient;
import org.wildfly.sasl.util.Charsets;
import org.wildfly.sasl.util.SaslState;
import org.wildfly.sasl.util.SaslStateContext;
import org.wildfly.sasl.util.SaslWrapper;

/**
 * SaslClient for the GSSAPI mechanism as defined by RFC 4752
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class GssapiClient extends AbstractSaslClient {

    // QOP
    private static final String AUTH = "auth";
    private static final String AUTH_INT = "auth-int";
    private static final String AUTH_CONF = "auth-conf";

    // Security Layer
    private static final byte NO_SECURITY_LAYER = (byte) 0x01;
    private static final byte INTEGRITY_PROTECTION = (byte) 0x02;
    private static final byte CONFIDENTIALITY_PROTECTION = (byte) 0x04;

    private static final int DEFAULT_MAX_BUFFER_SIZE = (int) 0xFFF; // We need to be able to specify this in three bytes.

    // Kerberos V5 OID

    public static final Oid KERBEROS_V5;

    static {
        try {
            KERBEROS_V5 = new Oid("1.2.840.113554.1.2.2");
        } catch (GSSException e) {
            throw new RuntimeException("Unable to initialise Oid", e);
        }
    }

    // Configured Values
    private final String authorizationId;
    private final QOP[] preferredQop;
    private final int configuredMaxReceiveBuffer;
    private final boolean relaxComplianceChecks;
    // Negotiated Values
    private QOP selectedQop;
    // Other Internal State
    private final GSSContext gssContext;

    GssapiClient(final String protocol, final String serverName, final Map<String, ?> props,
            final CallbackHandler callbackHandler, final String authorizationId) throws SaslException {
        super(AbstractGssapiFactory.GSSAPI, protocol, serverName, callbackHandler, authorizationId, true);

        this.authorizationId = authorizationId;
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

        // Initialise our GSSContext
        GSSManager manager = GSSManager.getInstance();

        String acceptorNameString = protocol + "@" + serverName;
        final GSSName acceptorName;
        try {
            // The client can use other name types but this should be added to the config.
            acceptorName = manager.createName(acceptorNameString, GSSName.NT_HOSTBASED_SERVICE, KERBEROS_V5);
        } catch (GSSException e) {
            throw new SaslException("Unable to create name for acceptor.", e);
        }

        preferredQop = parsePreferredQop((String) props.get(Sasl.QOP));
        boolean mayRequireSecurityLayer = mayRequireSecurityLater(preferredQop);

        // Pull the credential if we have it.
        GSSCredential credential = null;

        Object credObj = props.get(Sasl.CREDENTIALS);
        if (credObj != null && credObj instanceof GSSCredential) {
            credential = (GSSCredential) credObj;
        }

        // Better way to obtain the credential if we don't have one?

        final GSSContext gssContext;
        try {
            gssContext = manager.createContext(acceptorName, KERBEROS_V5, credential, GSSContext.INDEFINITE_LIFETIME);
        } catch (GSSException e) {
            throw new SaslException("Unable to crate GSSContexr", e);
        }

        try {
            // JDK only sets this if a credential was supplied, we should support a config override.
            // i.e. we may have a credential because it was delegated to us - doesn't mean we want
            // to delegate it further - at same point we may have a Subject on ACC and still want to delegate.
            boolean delegate = credential != null;
            if (props.containsKey(WildFlySasl.GSSAPI_DELEGATE_CREDENTIAL)) {
                delegate = Boolean.parseBoolean((String) props.get(WildFlySasl.GSSAPI_DELEGATE_CREDENTIAL));
            }
            if (delegate) {
                gssContext.requestCredDeleg(true);
            }

            // The client must pass the integ_req_flag of true.
            gssContext.requestInteg(true);
            // This was requested so that integrity protection can be used to negotiate the security layer,
            // further integrity protection will be based on the negotiated security layer.

            // requestMutualAuth if: -
            // 1 - The client requests it.
            // 2 - The client will be requesting a security layer. Will interpret as may be requesting as
            // client and server could agree auth only.
            boolean serverAuth = false;
            if (props.containsKey(Sasl.SERVER_AUTH)) {
                serverAuth = Boolean.parseBoolean((String) props.get(Sasl.SERVER_AUTH));
            }

            if (serverAuth || mayRequireSecurityLayer) {
                gssContext.requestMutualAuth(true);
            }

            // Request sequence detection if a security layer could be requested.
            if (mayRequireSecurityLayer) {
                gssContext.requestSequenceDet(true);
            }

            // Need to set this is we may want confidentiality, integrity is always requested.
            for (QOP current : preferredQop) {
                if (current == QOP.AUTH_CONF) {
                    gssContext.requestConf(true);
                    break;
                }
            }

        } catch (GSSException e) {
            throw new SaslException("Unable to set request flags.", e);
        }

        // Channel Binding Is Not Supported

        this.gssContext = gssContext;
    }

    private QOP[] parsePreferredQop(final String qop) throws SaslException {
        if (qop != null) {
            String[] qopNames = qop.split(", ");
            if (qopNames.length > 0) {
                QOP[] preferredQop = new QOP[qopNames.length];
                for (int i = 0; i < qopNames.length; i++) {
                    QOP mapped = QOP.mapFromName(qopNames[i]);
                    if (mapped == null) {
                        throw new SaslException(String.format("Unrecogniesed QOP value '%s'", qopNames[i]));
                    }
                    preferredQop[i] = mapped;

                }
                return preferredQop;
            }

        }

        return new QOP[] { QOP.AUTH };
    }

    /**
     * Converts bytes in network byte order to an integer starting from the specified offset.
     *
     * This method is implemented in the context of the GSSAPI mechanism, it is assumed that the size of the byte array is
     * appropriate.
     */
    private int networkOrderBytesToInt(final byte[] bytes, final int start) {
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
    private byte[] intToNetworkOrderBytes(final int value) {
        byte[] response = new byte[3];
        int workingValue = value;
        for (int i = response.length - 1; i < 0; i--) {
            response[i] = (byte) (workingValue & 0xFF);
            workingValue >>>= 8;
        }

        return response;
    }

    private boolean mayRequireSecurityLater(final QOP[] preferredQop) {
        for (QOP current : preferredQop) {
            if (current == QOP.AUTH_INT || current == QOP.AUTH_CONF) {
                return true;
            }
        }
        return false;
    }

    private QOP findAgreeableQop(final byte securityLayer) throws SaslException {
        for (QOP current : preferredQop) {
            if (current.includedBy(securityLayer)) {
                return current;
            }
        }

        throw new SaslException("No mutually agreeable security layer found.");
    }

    @Override
    public void init() {
        getContext().setNegotiationState(new InitialChallengeState());
    }

    @Override
    public Object getNegotiatedProperty(String propName) {
        if (isComplete() == false) {
            throw new IllegalStateException("The authentication exchange is not complete.");
        }

        switch (propName) {
            case Sasl.QOP:
                return selectedQop.getName();
        }

        // Properties to support: -
        // Sasl.MAX_BUFFER
        // Sasl.RAW_SEND_SIZE
        // MAX_SEND_BUF
        return null;
    }

    /**
     * GSSAPI is a client first mechanism, this state both verifies that requirement is met and provides the first token from
     * the client.
     *
     */
    private class InitialChallengeState implements SaslState {

        @Override
        public byte[] evaluateMessage(SaslStateContext context, byte[] message) throws SaslException {
            assert gssContext.isEstablished() == false;
            if (message.length > 0) {
                throw new SaslException("GSSAPI is a client first mechanism, unexpected server challenge received.");
            }

            try {
                byte[] response = gssContext.initSecContext(NO_BYTES, 0, 0);
                context.setNegotiationState(gssContext.isEstablished() ? new SecurityLayerNegotiationState()
                        : new ChallengeResponseState());
                return response;
            } catch (GSSException e) {
                throw new SaslException("Unable to create output token.", e);
            }
        }

    }

    /**
     * This state is to handle the subsequent exchange of tokens up until the point the GSSContext is established.
     *
     */
    private class ChallengeResponseState implements SaslState {

        @Override
        public byte[] evaluateMessage(SaslStateContext context, byte[] message) throws SaslException {
            assert gssContext.isEstablished() == false;

            try {
                byte[] response = gssContext.initSecContext(message, 0, message.length);

                if (gssContext.isEstablished()) {
                    // TODO - Before transitioning to next state verify requirements for clients security policy have been met.

                    context.setNegotiationState(new SecurityLayerNegotiationState());
                }
                return response;
            } catch (GSSException e) {
                throw new SaslException("Unable to handle response from server.", e);
            }
        }

    }

    private class SecurityLayerNegotiationState implements SaslState {

        @Override
        public byte[] evaluateMessage(SaslStateContext context, byte[] message) throws SaslException {
            MessageProp msgProp = new MessageProp(0, false);
            try {
                byte[] unwrapped = gssContext.unwrap(message, 0, message.length, msgProp);
                if (unwrapped.length != 4) {
                    throw new SaslException("Bad length of message for negotiating security layer.");
                }

                byte qopByte = unwrapped[0];
                selectedQop = findAgreeableQop(qopByte);
                int serverMaxMessageSize = networkOrderBytesToInt(unwrapped, 1);
                if (relaxComplianceChecks == false && serverMaxMessageSize > 0 && (qopByte & QOP.AUTH_INT.getValue()) == 0
                        && (qopByte & QOP.AUTH_CONF.getValue()) == 0) {
                    throw new SaslException(String.format(
                            "Invalid message size received when no security layer supported by server '%d'",
                            serverMaxMessageSize));
                }

                System.out
                        .println(String.format("Chosen QOP '%s', max Length %d", selectedQop.getName(), serverMaxMessageSize)); // TODO
                                                                                                                                // Remove

                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                baos.write(selectedQop.getValue());
                if (selectedQop == QOP.AUTH) {
                    // No security layer selected to must set response to 000.
                    baos.write(new byte[] { 0x00, 0x00, 0x00 });
                } else {
                    int actualMacReceiveBuffer = gssContext.getWrapSizeLimit(0, selectedQop == QOP.AUTH_CONF,
                            configuredMaxReceiveBuffer);
                    baos.write(intToNetworkOrderBytes(actualMacReceiveBuffer));
                }

                if (authorizationId != null) {
                    baos.write(authorizationId.getBytes(Charsets.UTF_8));
                }

                byte[] response = baos.toByteArray();
                msgProp = new MessageProp(0, false);
                response = gssContext.wrap(response, 0, response.length, msgProp);

                if (selectedQop != QOP.AUTH) {
                    setWrapper(new GssapiWrapper());
                }

                context.negotiationComplete();
                return response;
            } catch (IOException e) {
                throw new SaslException("Unable to construct response for server.", e);
            } catch (GSSException e) {
                throw new SaslException("Unable to unwrap security layer negotiation message.", e);
            }
        }
    }

    private class GssapiWrapper implements SaslWrapper {

        @Override
        public byte[] wrap(byte[] outgoing, int offset, int len) throws SaslException {
            MessageProp prop = new MessageProp(0, selectedQop == QOP.AUTH_CONF);
            try {
                return gssContext.wrap(outgoing, offset, len, prop);
            } catch (GSSException e) {
                throw new SaslException("Unable to wrap message.", e);
            }
        }

        @Override
        public byte[] unwrap(byte[] incoming, int offset, int len) throws SaslException {
            MessageProp prop = new MessageProp(0, selectedQop == QOP.AUTH_CONF);
            try {
                return gssContext.unwrap(incoming, offset, len, prop);
            } catch (GSSException e) {
                throw new SaslException("Unable to wrap message.", e);
            }
        }

    }

    private enum QOP {

        AUTH(GssapiClient.AUTH, NO_SECURITY_LAYER), AUTH_INT(GssapiClient.AUTH_INT, INTEGRITY_PROTECTION), AUTH_CONF(
                GssapiClient.AUTH_CONF, CONFIDENTIALITY_PROTECTION);

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
                case GssapiClient.AUTH:
                    return AUTH;
                case GssapiClient.AUTH_INT:
                    return AUTH_INT;
                case GssapiClient.AUTH_CONF:
                    return AUTH_CONF;
                default:
                    return null;
            }

        }

    }

}
