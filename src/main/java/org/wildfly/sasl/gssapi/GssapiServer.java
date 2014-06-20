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
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;

/**
 * SaslServer for the GSSAPI mechanism as defined by RFC 4752
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class GssapiServer extends AbstractGssapiMechanism implements SaslServer {

    GssapiServer(final String protocol, final String serverName, final Map<String, ?> props, final CallbackHandler callbackHandler) throws SaslException {
        super(AbstractGssapiFactory.GSSAPI, protocol, serverName, props, callbackHandler);
    }

    @Override
    public String getAuthorizationID() {
        return null;
    }

    @Override
    public byte[] evaluateResponse(byte[] response) throws SaslException {
        return evaluateMessage(response);
    }


    // States

    // 1 - Acceptor State

    // 2 - Security Layer Advertiser

    // 3 - Security Layer Receiver
}
