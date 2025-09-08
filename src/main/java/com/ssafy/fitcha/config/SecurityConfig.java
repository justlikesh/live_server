package com.ssafy.fitcha.config;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.ssafy.fitcha.model.dto.User;
import com.ssafy.fitcha.security.oauth.CustomOAuth2UserService;
import com.ssafy.fitcha.security.oauth.CustomOidcUserService;
import com.ssafy.fitcha.util.JwtUtil;

import jakarta.servlet.http.HttpServletResponse;

@Configuration
public class SecurityConfig {

	@Autowired
	private CustomOAuth2UserService customOAuth2UserService;

	@Autowired
	private CustomOidcUserService customOidcUserService;

	@Autowired
	private JwtUtil jwtUtil;

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http.cors().and().csrf().disable().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
				.and().authorizeHttpRequests(auth -> auth
						// 모든 요청 허용 (테스트용)
						.anyRequest().permitAll())
				.exceptionHandling().authenticationEntryPoint((request, response, authException) -> {
					response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
				});

		return http.build();
	}
}
