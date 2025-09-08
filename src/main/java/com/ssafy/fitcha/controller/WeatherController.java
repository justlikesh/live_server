package com.ssafy.fitcha.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.ssafy.fitcha.model.dto.Weather;
import com.ssafy.fitcha.model.service.WeatherService;

import io.swagger.v3.oas.annotations.Operation;

// @RestController
// @RequestMapping("/weather")
public class WeatherController {

	// 생성자 의존성 주입
	private final WeatherService weatherService;

	public WeatherController(WeatherService weatherService) {
		this.weatherService = weatherService;

	}

	@Operation(summary = "날씨 조회", description = "사용자의 현재 위치(위도와 경도)정보를 바탕으로 날씨 정보 조회")
	@GetMapping
	public ResponseEntity<Weather> getWeather(@RequestParam double lat, @RequestParam double lon) {
		Weather currentWeather = weatherService.getCurrentWeather(lat, lon);
		return ResponseEntity.ok(currentWeather);
	}

}
