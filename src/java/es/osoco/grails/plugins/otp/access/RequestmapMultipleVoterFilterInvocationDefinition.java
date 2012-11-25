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

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.codehaus.groovy.grails.plugins.springsecurity.ReflectionUtils;
import org.springframework.security.web.FilterInvocation;

/**
 * Based on Grails Spring Security Core's <code><code>org.codehaus.groovy.grails.plugins.springsecurity.RequestmapFilterInvocationDefinition</code>.
 *
 * @author <a href='mailto:rafael.luque@osoco.es'>Rafael Luque</a>
 */
public class RequestmapMultipleVoterFilterInvocationDefinition extends AbstractMultipleVoterFilterInvocationDefinition {

	private boolean _initialized;

	@Override
	protected String determineUrl(final FilterInvocation filterInvocation) {
		HttpServletRequest request = filterInvocation.getHttpRequest();
		String requestUrl = request.getRequestURI().substring(request.getContextPath().length());
		return lowercaseAndStripQuerystring(requestUrl);
	}

	@Override
	protected void initialize() {
		if (_initialized) {
			return;
		}

		try {
			reset();
			_initialized = true;
		}
		catch (RuntimeException e) {
			_log.warn("Exception initializing; this is ok if it's at startup and due " +
					"to GORM not being initialized yet since the first web request will " +
					"re-initialize. Error message is: " + e.getMessage());
		}
	}

	/**
	 * Call at startup or when <code>Requestmap</code> instances have been added, removed, or changed.
	 */
	@Override
	public synchronized void reset() {
		Map<String, String> data = loadRequestmaps();
		resetConfigs();

		for (Map.Entry<String, String> entry : data.entrySet()) {
			compileAndStoreMapping(entry.getKey(), split(entry.getValue()));
		}

		if (_log.isTraceEnabled()) {
			_log.trace("configs: " + getConfigAttributeMap());
		}
	}

	protected Map<String, String> loadRequestmaps() {
		Map<String, String> data = new HashMap<String, String>();

		for (Object requestmap : ReflectionUtils.loadAllRequestmaps()) {
			String urlPattern = ReflectionUtils.getRequestmapUrl(requestmap);
			String configAttribute = ReflectionUtils.getRequestmapConfigAttribute(requestmap);
			data.put(urlPattern, configAttribute);
		}

		return data;
	}
}
