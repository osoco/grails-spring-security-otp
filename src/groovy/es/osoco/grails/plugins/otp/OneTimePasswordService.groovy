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
package es.osoco.grails.plugins.otp

import es.osoco.oath.totp.TOTP

import org.apache.commons.codec.binary.Base32
import org.apache.commons.logging.Log
import org.apache.commons.logging.LogFactory

/**
 * This class checks the validity of one-time passwords delegating to the groovy-OTP library.
 * 
 * @author <a href="mailto:rafael.luque@osoco.es">Rafael Luque</a>
 */ 
class OneTimePasswordService {

    int otpDigits
    String otpAlgorithm
    int preStepsWindow
    int postStepsWindow

    protected final Log logger = LogFactory.getLog(getClass())

    public boolean isPasswordValid(String presentedPassword, String secretKey) {
        def decodedSecretKey = new Base32().decode(secretKey)
        String hexDecodedSecretKey = decodedSecretKey.encodeHex().toString()
        int currentTimeSteps = stepsForUnixTime(new Date().time)
        def validWindow = (currentTimeSteps - preStepsWindow)..(currentTimeSteps + postStepsWindow)
        logger.debug "validating OTP in the window: $validWindow"

        validWindow.any { steps ->
            presentedPassword == TOTP.generateTOTP(
                hexDecodedSecretKey, 
                toStepsTimeHex(steps), 
                "$otpDigits".toString(), 
                otpAlgorithm)
        }
    }

    private int stepsForUnixTime(unixTimeInMillis) {
        int steps = unixTimeInMillis / 1000 / 30
        steps
    }

    private String toStepsTimeHex(int stepTime) {
        String steps = Long.toHexString(stepTime).toUpperCase()
        while (steps.length() < 16) {
            steps = "0" + steps;
        }
        steps
    }


}
