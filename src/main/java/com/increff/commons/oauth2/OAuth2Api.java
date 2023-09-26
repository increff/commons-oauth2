/*
 * Copyright (c) 2021. Increff
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */

package com.increff.commons.oauth2;

import java.io.IOException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.api.client.auth.oauth2.AuthorizationCodeTokenRequest;
import com.google.api.client.auth.oauth2.TokenResponse;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;

public class OAuth2Api {

	private static final String accessTokenUrl = "https://www.googleapis.com/oauth2/v4/token";
	private static final String oauth2User = "oauth2user";

	public static TokenResponse getToken(OAuth2TokenForm form) throws IOException {
		HttpTransport httpTransport = new NetHttpTransport();
		JacksonFactory jacksonFactory = JacksonFactory.getDefaultInstance();

		// Create request to Google
		GenericUrl genericUrl = new GenericUrl(accessTokenUrl);
		AuthorizationCodeTokenRequest request = new AuthorizationCodeTokenRequest(//
				httpTransport, jacksonFactory, genericUrl, form.getCode()//
		);
		// Set request POST parameters
		request//
				.set("redirect_uri", form.getRedirectUrl())//
				.set("client_id", form.getClientId())//
				.set("client_secret", form.getClientSecret())//
				.set("grant_type", "authorization_code");//
		// Execute request
		return request.execute();
	}

	public static String decodeJwt(String jwtToken) {
		String[] split_string = jwtToken.split("\\.");
		String base64EncodedBody = split_string[1];
		String body = new String(Base64.getDecoder().decode(base64EncodedBody));
		return body;
	}

	public static Map<String, Object> getMap(String json) throws IOException {
		ObjectMapper mapper = new ObjectMapper();
		Map<String, Object> map = new HashMap<String, Object>();
		// convert JSON string to Map
		map = mapper.readValue(json, new TypeReference<Map<String, Object>>() {
		});
		return map;
	}

	public static OAuth2User getUser(HttpServletRequest req) {
		return (OAuth2User) req.getSession().getAttribute(oauth2User);
	}

	public static void clearUser(HttpSession session) {
		session.removeAttribute(oauth2User);
	}
	
	public static void setError(HttpSession session, String error) {
		// Create OAuth2User
		OAuth2User user = new OAuth2User();
		user.setMessage(error);
		// Set user in session
		session.setAttribute(oauth2User, user);
	}


	public static String setUser(HttpSession session, TokenResponse tokenResponse) throws IOException {
		// Decode JWT
		String jwt = (String) tokenResponse.get("id_token");
		String jwtDecoded = OAuth2Api.decodeJwt(jwt);
		Map<String, Object> map = getMap(jwtDecoded);
		// Create OAuth2User
		String email = (String) map.get("email");
		String accessToken = (String) tokenResponse.get("access_token");
		OAuth2User user = new OAuth2User();
		user.setEmail(email);
		user.setAccessToken(accessToken);
		// Set user in session
		session.setAttribute(oauth2User, user);
		return user.getEmail();
	}
}
