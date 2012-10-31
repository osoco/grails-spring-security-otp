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
package es.osoco.grails.plugins.otp.userdetails

import org.codehaus.groovy.grails.plugins.springsecurity.GrailsUser
import org.springframework.security.core.GrantedAuthority

/**
 * Extends the default GrailsUser class to contain the secretKey attribute required to calculate
 * the one-time passwords.
 *
 * @author <a href='mailto:rafael.luque@osoco.es'>Rafael Luque</a>
 */
class GrailsOtpUser extends GrailsUser {

	String secretKey

	/**
	 * Constructor.
	 *
	 * @param username the username presented to the
	 *        <code>DaoAuthenticationProvider</code>
	 * @param password the password that should be presented to the
	 *        <code>DaoAuthenticationProvider</code>
	 * @param enabled set to <code>true</code> if the user is enabled
	 * @param accountNonExpired set to <code>true</code> if the account has not expired
	 * @param credentialsNonExpired set to <code>true</code> if the credentials have not expired
	 * @param accountNonLocked set to <code>true</code> if the account is not locked
	 * @param authorities the authorities that should be granted to the caller if they
	 *        presented the correct username and password and the user is enabled. Not null.
	 * @param id the id of the domain class instance used to populate this
	 * @param secretKey
	 */
	GrailsOtpUser(String username, String password, boolean enabled, boolean accountNonExpired,
	              boolean credentialsNonExpired, boolean accountNonLocked,
	              Collection<GrantedAuthority> authorities, Object id, String secretKey) {

		super(username, password, enabled, accountNonExpired,
			credentialsNonExpired, accountNonLocked, authorities, id)
		this.secretKey = secretKey
	}
}
