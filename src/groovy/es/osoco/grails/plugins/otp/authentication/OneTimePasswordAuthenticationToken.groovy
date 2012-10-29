/*
 * ====================================================================
 *    ____  _________  _________ 
 *   / __ \/ ___/ __ \/ ___/ __ \
 *  / /_/ (__  ) /_/ / /__/ /_/ /
 *  \____/____/\____/\___/\____/ 
 *
 *  ~ La empresa de los programadores profesionales ~
 *
 *  | http://osoco.es
 *  |
 *  | Edificio Moma Lofts
 *  | Planta 3, Loft 18
 *  | Ctra. Mostoles-Villaviciosa, Km 0,2
 *  | Mostoles, Madrid 28935 Spain
 *
 * ====================================================================
 *
 * Copyright 2012 OSOCO. All Rights Reserved.
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
package es.osoco.grails.plugins.otp.authentication

import org.apache.commons.logging.Log
import org.apache.commons.logging.LogFactory

import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.core.GrantedAuthority

/**
 * An {@link org.springframework.security.core.Authentication} implementation that is designed for simple presentation
 * of a username and one-time password.
 *
 * This class is based on {@link UsernamePasswordAuthenticationToken}'s source.
 *
 * @author <a href="mailto:rafael.luque@osoco.es">Rafael Luque</a>
 */
class OneTimePasswordAuthenticationToken extends AbstractAuthenticationToken {

    private final Object principal
    private Object credentials

    protected final Log logger = LogFactory.getLog(getClass())

    /**
     * This constructor can be safely used by any code that wishes to create a
     * <code>UsernamePasswordAuthenticationToken</code>, as the {@link
     * #isAuthenticated()} will return <code>false</code>.
     *
     */
    public OneTimePasswordAuthenticationToken(Object principal, Object credentials) {
        super(null)
        this.principal = principal
        this.credentials = credentials
        setAuthenticated(false)
    }

    /**
     * @deprecated use the list of authorities version
     */
    public OneTimePasswordAuthenticationToken(Object principal, Object credentials, GrantedAuthority[] authorities) {
        this(principal, credentials, Arrays.asList(authorities))
    }

    /**
     * This constructor should only be used by <code>AuthenticationManager</code> or <code>AuthenticationProvider</code>
     * implementations that are satisfied with producing a trusted (i.e. {@link #isAuthenticated()} = <code>true</code>)
     * authentication token.
     *
     * @param principal
     * @param credentials
     * @param authorities
     */
    public OneTimePasswordAuthenticationToken(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
        super(authorities)
        this.principal = principal
        this.credentials = credentials
        super.setAuthenticated(true) // must use super, as we override
    }


    public Object getCredentials() {
        return this.credentials
    }

    public Object getPrincipal() {
        return this.principal
    }

    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        if (isAuthenticated) {
            throw new IllegalArgumentException(
                "Cannot set this token to trusted - use constructor which takes a GrantedAuthority list instead")
        }

        super.setAuthenticated(false)
    }

    @Override
    public void eraseCredentials() {
        super.eraseCredentials()
        credentials = null
    }

}
