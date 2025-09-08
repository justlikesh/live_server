package com.ssafy.fitcha.util;

import java.nio.charset.StandardCharsets;
import java.util.Date;

import javax.crypto.SecretKey;

import org.springframework.stereotype.Component;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtUtil {
    // JWT 서명을 위한 비밀키 문자열 (실제 환경에서는 더 안전하게 관리 필요)
    private String key = "SSAFY_fitcha_project_token_SecretKey_!@#$%!@$";
    
    // 비밀키를 HMAC SHA 알고리즘에 맞게 변환한 객체
    private SecretKey secretKey = Keys.hmacShaKeyFor(key.getBytes(StandardCharsets.UTF_8));
    
    // 토큰 만료시간 설정 (여기서는 1시간, 개발 시 테스트 용도에 맞게 조절 가능)
    private final long EXPIRATION_TIME = 1000 * 60 * 60; // 1시간

    /**
     * 토큰 생성 메서드
     * @param userId - 토큰에 저장할 사용자 식별자
     * @return 생성된 JWT 토큰 문자열
     */
    public String createToken(String userId) {
        Date now = new Date();  // 현재 시간
        Date exp = new Date(now.getTime() + EXPIRATION_TIME);  // 만료 시간 설정

        // JWT 토큰 빌드
        return Jwts.builder()
                .setSubject(userId)      // 토큰 주체(subject)에 userId 저장
                .setIssuedAt(now)        // 발급 시간 기록
                .setExpiration(exp)      // 만료 시간 기록
                .signWith(secretKey)     // 비밀키로 서명 (토큰 위변조 방지)
                .compact();              // 최종 토큰 문자열 생성
    }

    /**
     * 토큰 유효성 검사 메서드
     * @param token 검사할 JWT 토큰 문자열
     * @return 유효하면 true, 그렇지 않으면 false 반환
     */
    public boolean validateToken(String token) {
        try {
            // JWT 파서로 서명키를 사용해 토큰 검증 시도
            Jwts.parser()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token);
            return true;    // 검증 성공 시 true 반환
        } catch (Exception e) {
            return false;   // 검증 실패 시 false 반환
        }
    }

    /**
     * 토큰에서 userId(Subject) 추출
     * @param token JWT 토큰 문자열
     * @return 토큰의 subject(즉, userId) 문자열 반환
     */
    public String getUserId(String token) {
        return Jwts.parser()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    /**
     * secretKey를 외부에서 사용할 수 있도록 getter 제공
     * 주로 JWT 토큰 검증을 위해 필터에서 사용
     * @return SecretKey 객체 반환
     */
    public SecretKey getSecretKey() {
        return secretKey;
    }
}
