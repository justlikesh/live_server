package com.ssafy.fitcha.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import com.ssafy.fitcha.interceptor.LoginInterceptor;

@Configuration
public class WebConfig implements WebMvcConfigurer {

	@Autowired
	LoginInterceptor loginInterceptor;

//	@Override
//	public void addInterceptors(InterceptorRegistry registry) {
//		
//		registry.addInterceptor(loginInterceptor) // 인터셉터 등록
//				.addPathPatterns("/**") // 매핑할 url 지정
//				.excludePathPatterns("/user/login","/main"); // 제외할 url 지정
//	}
//	
	// 교차 출처 리소스 공유(CORS) 전역 설정
	@Override
	public void addCorsMappings(CorsRegistry registry) {
		registry.addMapping("/**").allowedOrigins("http://localhost:5173") // 프론트 주소
				.allowedOriginPatterns("*")// 출처 도메인 (현재는 개발중이라 전체로 설정)-> 추후 나의 프론트엔드 도메인으로 변경 필요
				.allowedMethods("GET", "POST", "PUT", "DELETE").allowCredentials(true);
	}

	// 정적 리소스 핸들러 등록
	@Override
	public void addResourceHandlers(ResourceHandlerRegistry registry) {
		// "/uploads/**" 로 시작하는 요청을
		// 실제 파일 시스템의 "C:/SSAFY/" 폴더에 있는 파일로 응답하도록 설정
		registry.addResourceHandler("/upload/**")
		.addResourceLocations("file:///C:/SSAFY/upload/");
//				.addResourceLocations("file:///Users/ohsewon/Desktop/images/");
//				.addResourceLocations("file:///Users/hansol/Desktop/img/");

	}

}
