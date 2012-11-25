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
package es.osoco.grails.plugins.otp.access;

import java.util.Collection;

import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;

import es.osoco.grails.plugins.otp.userdetails.GrailsOtpUser;

/**
 * An {@link AccessDecisionVoter} implementation that votes if a {@link ConfigAttribute#getAttribute()}
 * of <code>IS_AUTHENTICATED_OTP</code> value is present.
 *
 * <p>
 * The current <code>Authentication</code> will be inspected to determine if the principal has a particular
 * level of authentication.
 *
 * <p>
 * All comparisons are case sensitive.
 *
 * @author Rafael Luque
 */
public class OneTimePasswordVoter implements AccessDecisionVoter {

	public static final String IS_AUTHENTICATED_OTP = "IS_AUTHENTICATED_OTP";

	public int vote(Authentication authentication, Object object, Collection<ConfigAttribute> attributes) {
		int result = ACCESS_ABSTAIN;

		for (ConfigAttribute attribute : attributes) {
			if (supports(attribute)) {
				result = isOtpAuthenticated(authentication) ? ACCESS_GRANTED : ACCESS_DENIED;
			}
		}

		return result;
	}

	public boolean supports(ConfigAttribute attribute) {
		return attribute != null && attribute.getAttribute() == OneTimePasswordVoter.IS_AUTHENTICATED_OTP;
	}

	/**
	 * This implementation supports any type of class, because it does not query the presented secure object.
	 *
	 * @param clazz the secure object
	 *
	 * @return always <code>true</code>
	 */
	public boolean supports(Class<?> clazz) {
		return true;
	}

	private boolean isOtpAuthenticated(Authentication authentication) {
		return authentication.getPrincipal() instanceof GrailsOtpUser;
	}
}
