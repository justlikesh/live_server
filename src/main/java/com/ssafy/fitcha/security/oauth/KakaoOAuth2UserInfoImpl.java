package com.ssafy.fitcha.security.oauth;

import java.util.Map;

//카카오에서 전달한 정보를 가져옴 (구글,네이버 등 각 공급자마다 전달하는 구조가 다름.)
public class KakaoOAuth2UserInfoImpl implements OAuth2UserInfo {

    private final Map<String, Object> attributes;

    public KakaoOAuth2UserInfoImpl(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    @Override
    public String getId() {
        return String.valueOf(attributes.get("id"));
    }

    @Override
    public String getEmail() {
        Map<String, Object> account = (Map<String, Object>) attributes.get("kakao_account");
        return (String) account.get("email");
    }

    @Override
    public String getNickname() {
        Map<String, Object> profile = (Map<String, Object>) ((Map<String, Object>) attributes.get("kakao_account")).get("profile");
        return (String) profile.get("nickname");
    }
}
