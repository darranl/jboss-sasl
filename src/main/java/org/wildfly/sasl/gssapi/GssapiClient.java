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
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;
import org.wildfly.sasl.util.AbstractSaslClient;
import org.wildfly.sasl.util.SaslState;
import org.wildfly.sasl.util.SaslStateContext;

/**
 * SaslClient for the GSSAPI mechanism as defined by RFC 4752
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class GssapiClient extends AbstractSaslClient {

    // Security Layer
    private final byte NO_SECURITY_LAYER = (byte) 0x01;
    private final byte INTEGRITY_PROTECTION = (byte) 0x02;
    private final byte CONFIDENTIALITY_PROTECTION = (byte) 0x04;

    // Kerberos V5 OID

    public static final Oid KERBEROS_V5;

    static
    {
       try
       {
          KERBEROS_V5 = new Oid("1.2.840.113554.1.2.2");
       }
       catch (GSSException e)
       {
          throw new RuntimeException("Unable to initialise Oid", e);
       }
    }

    private final GSSContext gssContext;

    GssapiClient(final String protocol, final String serverName, final Map<String, ?> props,
            final CallbackHandler callbackHandler, final String authorizationId) throws SaslException {
        super(AbstractGssapiFactory.GSSAPI, protocol, serverName, callbackHandler, authorizationId, true);

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
            // gssContext.requestCredDeleg(state);

            // The client must pass the integ_req_flag of true.
            gssContext.requestInteg(true);
            // This was requested so that integrity protection can be used to negotiate the security layer,
            // further integrity protection will be based on the negotiated security layer.

            // requestMutualAuth if: -
            // 1 - The client requests it.
            // 2 - The client will be requesting a security layer. Will interpret as may be requesting as
            // client and server could agree auth only.
            // gssContext.requestMutualAuth(state);

            // Request sequence detection if a security layer could be requested.
            // gssContext.requestSequenceDet(state);
            // Need to set this is we may want confidentiality, integrity is always requested.
            // gssContext.requestConf(state);

        } catch (GSSException e) {
            throw new SaslException("Unable to set request flags.", e);
        }

        // Channel Binding Is Not Supported

        this.gssContext = gssContext;
    }

    @Override
    public void init() {
        getContext().setNegotiationState(new InitialChallengeState());
    }

    /**
     * GSSAPI is a client first mechanism, this state both verifies that requirement is met and provides the first token from
     * the client.
     *
     */
    private class InitialChallengeState implements SaslState {

        @Override
        public byte[] evaluateMessage(SaslStateContext context, byte[] message) throws SaslException {
            if (message.length > 0) {
                throw new SaslException("GSSAPI is a client first mechanism, unexpected server challenge received.");
            }

            try {
                byte[] response = gssContext.initSecContext(NO_BYTES, 0, 0);
                context.setNegotiationState(gssContext.isEstablished() ? new SecurityLayerNegotiationState() : new ChallengeResponseState());
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

            // Before transitioning to next state verify requirements for clients security policy have been met.
            return NO_BYTES;
        }

    }

    private class SecurityLayerNegotiationState implements SaslState {

        @Override
        public byte[] evaluateMessage(SaslStateContext context, byte[] message) throws SaslException {
            // TODO Auto-generated method stub
            return NO_BYTES;
        }

    }

}
