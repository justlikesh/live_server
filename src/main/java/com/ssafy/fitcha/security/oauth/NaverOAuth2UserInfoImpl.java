package com.ssafy.fitcha.security.oauth;

import java.util.Map;

@SuppressWarnings("unchecked")
public class NaverOAuth2UserInfoImpl implements OAuth2UserInfo {

    private final Map<String,Object> response;

    public NaverOAuth2UserInfoImpl(Map<String,Object> attributes) {
        this.response = attributes;  // 이제 null 아님!
    }
    @Override public String getId()       { return (String) response.get("id"); }
    @Override public String getEmail()    { return (String) response.get("email"); }
    @Override public String getNickname() { return (String) response.get("nickname"); }
}