package com.ssafy.fitcha.security.oauth;

import java.util.Map;

public class GoogleOAuth2UserInfoImpl implements OAuth2UserInfo {
    private Map<String, Object> attributes;
    public GoogleOAuth2UserInfoImpl(Map<String, Object> attributes) {
        this.attributes = attributes;
    }
    @Override public String getId()       { return (String) attributes.get("sub"); }
    @Override public String getEmail()    { return (String) attributes.get("email"); }
    @Override public String getNickname() { return (String) attributes.get("name"); }
}