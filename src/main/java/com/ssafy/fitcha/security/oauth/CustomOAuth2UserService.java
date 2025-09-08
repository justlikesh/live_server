package com.ssafy.fitcha.security.oauth;

import java.util.Collections;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import com.ssafy.fitcha.model.dto.User;
import com.ssafy.fitcha.model.service.UserService;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;

//회원가입으로 갈지 메인으로 갈지 정해야하 하므로 추가 

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

	@Autowired
	private UserService userService;
	@Autowired
	private HttpServletRequest request;
	private final RestOperations rest = new RestTemplate();

	@Override
	public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

		String registrationId = userRequest.getClientRegistration().getRegistrationId();

		// 로그인 후 돌아올 때 쓸 이름 속성("id" or "sub")
		String userNameAttr = userRequest.getClientRegistration().getProviderDetails().getUserInfoEndpoint()
				.getUserNameAttributeName();

		Map<String, Object> attributes = null;
		OAuth2UserInfo userInfo;

		if ("naver".equals(registrationId)) {
			// 1) 토큰으로 헤더 설정
			HttpHeaders headers = new HttpHeaders();
			headers.setBearerAuth(userRequest.getAccessToken().getTokenValue());
			HttpEntity<Void> entity = new HttpEntity<>(headers);

			// 2) 전체 JSON(Map) 호출
			@SuppressWarnings("unchecked")
			Map<String, Object> result = rest
					.exchange(userRequest.getClientRegistration().getProviderDetails().getUserInfoEndpoint().getUri(),
							HttpMethod.GET, entity, Map.class)
					.getBody();

			// 3) inner "response" 맵만 꺼내서 새로운 변수에 담기
			@SuppressWarnings("unchecked")
			Map<String, Object> responseMap = (Map<String, Object>) result.get("response");

			// 4) responseMap 으로 userInfo 객체 생성
			userInfo = new NaverOAuth2UserInfoImpl(responseMap);

			// 5) DefaultOAuth2User 에 넘길 attributes 도 덮어쓰기
			attributes = responseMap;
		} else {
			// ── 카카오·구글은 기본 서비스 사용 ──
			OAuth2User delegate = new DefaultOAuth2UserService().loadUser(userRequest);
			attributes = delegate.getAttributes();

			if ("kakao".equals(registrationId)) {
				userInfo = new KakaoOAuth2UserInfoImpl(attributes);
			} else if ("google".equals(registrationId)) {
				userInfo = new GoogleOAuth2UserInfoImpl(attributes);
			} else {
				throw new OAuth2AuthenticationException("지원하지 않는 소셜 로그인: " + registrationId);
			}
		}

		// ── 기존 DB 로그인/가입 분기 ──
		User user = new User();
		user.setUserId(userInfo.getEmail());
		User DBuser = userService.login(user);
		request.getSession().setAttribute("signupStatus", DBuser == null ? "true" : "false");

		if (DBuser != null) {
			request.getSession().setAttribute("user", DBuser);

		} else
			request.getSession().setAttribute("user", user);

		// ── 최종 사용자 객체 생성 ──
		return new DefaultOAuth2User(Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")), attributes,
				userNameAttr);
	}
}
