package com.ssafy.fitcha.model.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description="날씨 정보 DTO")
public class Weather {
	private String temperature; // 온도
	private String humidity; // 습도
	private String rain; // 비
	private String sky; // 하늘
	
	public Weather() {
	}

	public String getRain() {
		return rain;
	}

	public void setRain(String rain) {
		this.rain = rain;
	}

	public String getTemperature() {
		return temperature;
	}

	public void setTemperature(String temperature) {
		this.temperature = temperature;
	}

	public String getHumidity() {
		return humidity;
	}

	public void setHumidity(String humidity) {
		this.humidity = humidity;
	}

	public String getSky() {
		return sky;
	}

	public void setSky(String sky) {
		this.sky = sky;
	}

	@Override
	public String toString() {
		return "Weather [temperature=" + temperature + ", humidity=" + humidity + ", rain=" + rain + ", sky=" + sky
				+ "]";
	}


	
	
	
	
}
