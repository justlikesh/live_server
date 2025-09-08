package com.ssafy.fitcha.interceptor;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.WebSocketHandler;
import org.springframework.web.socket.server.HandshakeInterceptor;

import com.ssafy.fitcha.util.JwtUtil;

import jakarta.servlet.http.HttpServletRequest;

@Component
public class JwtHandshakeInterceptor implements HandshakeInterceptor {

	private final JwtUtil jwtUtil;

	@Autowired
	public JwtHandshakeInterceptor(JwtUtil jwtUtil) {
		this.jwtUtil = jwtUtil;
	}

	@Override
	public boolean beforeHandshake(ServerHttpRequest request, ServerHttpResponse response, WebSocketHandler wsHandler,
			Map<String, Object> attributes) {

		if (request instanceof ServletServerHttpRequest servletRequest) {
			HttpServletRequest httpRequest = servletRequest.getServletRequest();
			String token = httpRequest.getParameter("token");

			if (token != null && jwtUtil.validateToken(token)) {
				String userId = jwtUtil.getUserId(token);
				attributes.put("userId", userId);
				return true;
			}
		}

		response.setStatusCode(org.springframework.http.HttpStatus.UNAUTHORIZED);
		return false;
	}

	@Override
	public void afterHandshake(ServerHttpRequest request, ServerHttpResponse response, WebSocketHandler wsHandler,
			Exception exception) {
		// No-op
	}
}
