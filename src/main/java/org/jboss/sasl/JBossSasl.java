/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2013, Red Hat, Inc., and individual contributors
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
package org.jboss.sasl;

import java.security.Provider;
import java.security.Security;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;

import org.jboss.idm.IdentityManager;

/**
 * A JBoss equivalent of {@link Sasl}
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class JBossSasl {

    private static final String JBOSS_SASL_SERVER_FACTORY = JBossSaslServerFactory.class.getSimpleName();

    private static final String DOT = ".";

    // No instantiation.
    private JBossSasl() {
    }

    public static final String QOP = Sasl.QOP;
    public static final String STRENGTH = Sasl.STRENGTH;
    public static final String SERVER_AUTH = Sasl.SERVER_AUTH;
    public static final String MAX_BUFFER = Sasl.MAX_BUFFER;
    public static final String RAW_SEND_SIZE = Sasl.RAW_SEND_SIZE;
    public static final String REUSE = Sasl.REUSE;
    public static final String POLICY_NOPLAINTEXT = Sasl.POLICY_NOPLAINTEXT;
    public static final String POLICY_NOACTIVE = Sasl.POLICY_NOACTIVE;
    public static final String POLICY_NODICTIONARY = Sasl.POLICY_NODICTIONARY;
    public static final String POLICY_NOANONYMOUS = Sasl.POLICY_NOANONYMOUS;
    public static final String POLICY_FORWARD_SECRECY = Sasl.POLICY_FORWARD_SECRECY;
    public static final String POLICY_PASS_CREDENTIALS = Sasl.POLICY_PASS_CREDENTIALS;
    public static final String CREDENTIALS = Sasl.CREDENTIALS;

    public static SaslClient createSaslClient(String[] mechanisms, String authorizationId, String protocol, String serverName,
            Map<String, ?> props, CallbackHandler cbh) throws SaslException {
        return Sasl.createSaslClient(mechanisms, authorizationId, protocol, serverName, props, cbh);
    }

    public static SaslServer createSaslServer(String mechanism, String protocol, String serverName, Map<String, ?> props,
            IdentityManager idm) throws SaslException {
        SaslServer mech = null;
        JBossSaslServerFactory fac;
        String className;

        if (mechanism == null) {
            throw new NullPointerException("Mechanism name cannot be null");
        } else if (mechanism.length() == 0) {
            return null;
        }

        String mechFilter = JBOSS_SASL_SERVER_FACTORY + DOT + mechanism;
        Provider[] provs = Security.getProviders(mechFilter);
        for (int j = 0; provs != null && j < provs.length; j++) {
            className = provs[j].getProperty(mechFilter);
            if (className == null) {
                throw new SaslException("Provider does not support " +
                    mechFilter);
            }
            fac = (JBossSaslServerFactory) loadFactory(provs[j], className);
            if (fac != null) {
                mech = fac.createSaslServer(
                    mechanism, protocol, serverName, props, idm);
                if (mech != null) {
                    return mech;
                }
            }
        }

        return null;
    }

    public static Enumeration<SaslClientFactory> getSaslClientFactories() {
        return Sasl.getSaslClientFactories();
    }

    public static Enumeration<JBossSaslServerFactory> getSaslServerFactories() {
        Set<Object> facs = getFactories(JBOSS_SASL_SERVER_FACTORY);
        final Iterator<Object> iter = facs.iterator();
        return new Enumeration<JBossSaslServerFactory>() {
            public boolean hasMoreElements() {
                return iter.hasNext();
            }
            public JBossSaslServerFactory nextElement() {
                return (JBossSaslServerFactory)iter.next();
            }
        };
    }

    private static Object loadFactory(Provider p, String className)
            throws SaslException {
            try {
                /*
                 * Load the implementation class with the same class loader
                 * that was used to load the provider.
                 * In order to get the class loader of a class, the
                 * caller's class loader must be the same as or an ancestor of
                 * the class loader being returned. Otherwise, the caller must
                 * have "getClassLoader" permission, or a SecurityException
                 * will be thrown.
                 */
                ClassLoader cl = p.getClass().getClassLoader();
                Class implClass;
                implClass = Class.forName(className, true, cl);
                return implClass.newInstance();
            } catch (ClassNotFoundException e) {
                throw new SaslException("Cannot load class " + className, e);
            } catch (InstantiationException e) {
                throw new SaslException("Cannot instantiate class " + className, e);
            } catch (IllegalAccessException e) {
                throw new SaslException("Cannot access class " + className, e);
            } catch (SecurityException e) {
                throw new SaslException("Cannot access class " + className, e);
            }
        }

    private static Set<Object> getFactories(String serviceName) {
        HashSet<Object> result = new HashSet<Object>();

        if ((serviceName == null) || (serviceName.length() == 0) ||
            (serviceName.endsWith("."))) {
            return result;
        }


        Provider[] providers = Security.getProviders();
        HashSet<String> classes = new HashSet<String>();
        Object fac;

        for (int i = 0; i < providers.length; i++) {
            classes.clear();

            // Check the keys for each provider.
            for (Enumeration e = providers[i].keys(); e.hasMoreElements(); ) {
                String currentKey = (String)e.nextElement();
                if (currentKey.startsWith(serviceName)) {
                    // We should skip the currentKey if it contains a
                    // whitespace. The reason is: such an entry in the
                    // provider property contains attributes for the
                    // implementation of an algorithm. We are only interested
                    // in entries which lead to the implementation
                    // classes.
                    if (currentKey.indexOf(" ") < 0) {
                        String className = providers[i].getProperty(currentKey);
                        if (!classes.contains(className)) {
                            classes.add(className);
                            try {
                                fac = loadFactory(providers[i], className);
                                if (fac != null) {
                                    result.add(fac);
                                }
                            }catch (Exception ignore) {
                            }
                        }
                    }
                }
            }
        }
        return Collections.unmodifiableSet(result);
    }

}
