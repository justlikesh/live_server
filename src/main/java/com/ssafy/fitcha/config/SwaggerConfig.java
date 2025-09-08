package com.ssafy.fitcha.config;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.swagger.v3.oas.models.ExternalDocumentation;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;

//http://localhost:8080/swagger-ui/index.html 검색
@Configuration
public class SwaggerConfig {

	 @Bean
	  public OpenAPI springFitchaOpenAPI() {
	      return new OpenAPI()
	              .info(new Info().title("SpringFitcha API")
	              .description("Spring boot Fitcha REST API")
	              .version("v0.0.1")
	              .license(new License().name("SSAFY").url("https://www.ssafy.com")))
	              .externalDocs(new ExternalDocumentation());
	           
	  }
}
