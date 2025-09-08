package com.ssafy.fitcha.security.oauth;

import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
public class CustomOidcUserService
    implements OAuth2UserService<OidcUserRequest, OidcUser> {

  private final CustomOAuth2UserService delegate;  // 기존 OAuth2UserService 재사용

  public CustomOidcUserService(CustomOAuth2UserService delegate) {
    this.delegate = delegate;
  }

  @Override
  public OidcUser loadUser(OidcUserRequest userRequest) 
      throws OAuth2AuthenticationException {
    // 1) OpenID Connect 표준 서비스로 먼저 OidcUser를 로드
    OidcUser oidcUser = new OidcUserService().loadUser(userRequest);

    // 2) 다시 OAuth2UserRequest 형태로 위임하여 공통 로직 수행
    //    (구현 편의를 위해 userRequest를 OAuth2형으로 캐스팅)
    OAuth2User oauth2User = delegate.loadUser(userRequest);

    // 3) 필요한 경우 oidcUser의 속성과 oauth2User의 속성을 병합 가능
    return oidcUser;  // 또는 새 DefaultOidcUser로 구성
  }
}
