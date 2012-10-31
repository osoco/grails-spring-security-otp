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
package es.osoco.grails.plugins.otp;

import org.apache.commons.codec.binary.Base32;
import org.codehaus.groovy.runtime.EncodingGroovyMethods;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import es.osoco.oath.totp.TOTP;

/**
 * Checks the validity of one-time passwords delegating to the groovy-OTP library.
 *
 * @author <a href="mailto:rafael.luque@osoco.es">Rafael Luque</a>
 */
public class OneTimePasswordService {

	private int otpDigits;
	private String otpAlgorithm;
	private int preStepsWindow;
	private int postStepsWindow;

	private Base32 base32 = new Base32();

	protected final Logger logger = LoggerFactory.getLogger(getClass());

	public boolean isPasswordValid(String presentedPassword, String secretKey) {
		byte[] decodedSecretKey = base32.decode(secretKey);
		String hexDecodedSecretKey = EncodingGroovyMethods.encodeHex(decodedSecretKey).toString();
		int currentTimeSteps = stepsForUnixTime(System.currentTimeMillis());

		int validWindowStart = currentTimeSteps - preStepsWindow;
		int validWindowEnd = currentTimeSteps + postStepsWindow;
		logger.debug("validating OTP in the window: {}..{}", new Object[] { validWindowStart, validWindowEnd });

		for (int steps = validWindowStart; steps <= validWindowEnd; steps++) {
			if (TOTP.generateTOTP(
					hexDecodedSecretKey,
					toStepsTimeHex(steps),
					String.valueOf(otpDigits),
					otpAlgorithm).equals(presentedPassword)) {
				return true;
			}
		}

		return false;
	}

	public void setOtpDigits(int otpDigits) {
		this.otpDigits = otpDigits;
	}

	public void setOtpAlgorithm(String otpAlgorithm) {
		this.otpAlgorithm = otpAlgorithm;
	}

	public void setPreStepsWindow(int preStepsWindow) {
		this.preStepsWindow = preStepsWindow;
	}

	public void setPostStepsWindow(int postStepsWindow) {
		this.postStepsWindow = postStepsWindow;
	}

	private int stepsForUnixTime(long unixTimeInMillis) {
		return (int)(unixTimeInMillis / 1000 / 30);
	}

	private String toStepsTimeHex(int stepTime) {
		String steps = Long.toHexString(stepTime).toUpperCase();
		while (steps.length() < 16) {
			steps = "0" + steps;
		}
		return steps;
	}
}
