package com.ssafy.fitcha.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

@Configuration
public class WebClientConfig {

	@Bean
	public WebClient youtubeWebClient() {
		// 기본 URL을 YouTube API 루트로 고정
		return WebClient.builder().baseUrl("https://www.googleapis.com/youtube/v3").build();
	}
	
	@Bean
	public WebClient weatherWebClient() {
		return WebClient.builder().defaultHeader("User-Agent", "Mozilla/5.0 (compatible; FitchaApp/1.0)").build();
	}
}