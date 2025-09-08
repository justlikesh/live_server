package com.ssafy.fitcha.config;

import java.io.IOException;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import com.ssafy.fitcha.util.JwtUtil;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * JWT 토큰을 이용하여 인증 처리하는 필터 클래스 - 모든 HTTP 요청마다 한 번 실행됨 (OncePerRequestFilter 상속)
 * - 요청 헤더의 Authorization에 담긴 JWT 토큰을 검사하여 인증 처리
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

	private final JwtUtil jwtUtil;

	/**
	 * JwtUtil 객체를 주입받아 토큰 검증 및 사용자 정보 추출에 사용
	 * 
	 * @param jwtUtil JWT 토큰 관련 유틸리티
	 */
	public JwtAuthenticationFilter(JwtUtil jwtUtil) {
		this.jwtUtil = jwtUtil;
	}

	/**
	 * 필터 동작 메서드 - 매 요청 시 호출됨
	 * 
	 * @param request     HTTP 요청 객체
	 * @param response    HTTP 응답 객체
	 * @param filterChain 다음 필터 체인
	 */
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		String path = request.getRequestURI();
		// WebSocket 연결은 필터 무시
		if (path.startsWith("/ws")) {
			filterChain.doFilter(request, response);
			return;
		}

		try {
			// 요청 헤더에서 JWT 토큰 추출
			String token = parseJwt(request);

			// 토큰이 존재하고 유효하다면 인증 처리
			if (token != null && jwtUtil.validateToken(token)) {
				// 토큰에서 userId 추출
				String userId = jwtUtil.getUserId(token);

				// 인증 객체 생성 (권한 정보는 null, 필요 시 구현 가능)
				UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userId,
						null, null);

				// 인증 객체에 요청 세부 정보 부여
				authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

				// Spring Security Context에 인증 정보 등록
				SecurityContextHolder.getContext().setAuthentication(authentication);
			}

			// 다음 필터로 요청 전달
			filterChain.doFilter(request, response);

		} catch (ExpiredJwtException e) {
			// JWT 토큰이 만료된 경우 401 상태코드와 메시지 응답
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED); // 401 Unauthorized
			response.setContentType("application/json;charset=UTF-8");
			response.getWriter().write("{\"message\":\"토큰이 만료되었습니다.\"}");
		} catch (JwtException | IllegalArgumentException e) {
			// JWT 토큰이 유효하지 않거나 파싱 오류가 발생한 경우 401 상태코드와 메시지 응답
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			response.setContentType("application/json;charset=UTF-8");
			response.getWriter().write("{\"message\":\"유효하지 않은 토큰입니다.\"}");
		}
	}

	/**
	 * HTTP 요청 헤더 Authorization에서 JWT 토큰 추출
	 * 
	 * @param request HTTP 요청 객체
	 * @return "Bearer " 접두사를 뗀 토큰 문자열 혹은 null 반환
	 */
	private String parseJwt(HttpServletRequest request) {
		String headerAuth = request.getHeader("Authorization");

		// Authorization 헤더가 존재하고 "Bearer "로 시작하면 토큰 추출
		if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
			return headerAuth.substring(7); // "Bearer " 제거 후 토큰 반환
		}

		return null; // 토큰이 없는 경우 null 반환
	}
}
