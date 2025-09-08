package com.ssafy.fitcha.model.service;

import com.ssafy.fitcha.model.dto.Weather;

public interface WeatherService {
	
	// lat : 위도 , lon : 경도
	Weather getCurrentWeather(double lat, double lon);
	
}
