package com.ssafy.fitcha.model.service;

import java.time.LocalDate;
import java.time.LocalTime;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.UriComponentsBuilder;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ssafy.fitcha.model.dto.Weather;
import com.ssafy.fitcha.util.GridUtil;

import jakarta.annotation.PostConstruct;

// @Service
public class WeatherServiceImpl implements WeatherService {

	// 생성자 주입
	private final WebClient weatherWebClient;
	private final GridUtil gridUtil;

	public WeatherServiceImpl(WebClient weatherWebClient, GridUtil gridUtil) {
		this.weatherWebClient = weatherWebClient;
		this.gridUtil = gridUtil;
	}

	@Value("${weather.api.key}")
	private String serviceKey;

	@Override
	public Weather getCurrentWeather(double lat, double lon) {

		int[] grid = gridUtil.convertToGridUtil(lat, lon); // 위도 경도를 좌표로 변환
		int nx = grid[0];
		int ny = grid[1];

		// 현재 날짜를 yyyyMMdd 형식으로 포맷팅
		String baseDate = LocalDate.now().format(DateTimeFormatter.BASIC_ISO_DATE);

		// 현재 시간
		LocalTime now = LocalTime.now();

		// baseTime 계산 (기상청 요구: 정시 기준, 10분 후부터 데이터 제공)
		if (now.getMinute() < 40) {
		    now = now.minusHours(1);
		}
		String baseTime = String.format("%02d30", now.getHour());


		// 초단기 실황 데이터
		String url = UriComponentsBuilder
				.fromHttpUrl("https://apis.data.go.kr/1360000/VilageFcstInfoService_2.0/getUltraSrtNcst")
				.queryParam("ServiceKey", serviceKey) // 인증키
				.queryParam("dataType", "JSON") // 응답 포맷
				.queryParam("base_date", baseDate) // 기준 날짜
				.queryParam("base_time", baseTime) // 기준 시간
				.queryParam("nx", nx) // 격자 X 좌표
				.queryParam("ny", ny) // 격자 Y 좌표
				.build(false) // 쿼리 파라미터에 인코딩하지 않음 (serviceKey 때문에)
				.toUriString(); // 최종 문자열로 반환

		String ncstJson = weatherWebClient.get().uri(url).retrieve() // 응답 수신
				.bodyToMono(String.class) // Mono로 비동기 응답처리 (String 타입으로 받음)
				.block(); // 비동기 -> 동기로 전환

		
		// 초단기 예보 데이터 (하늘 상태 얻어오기 위해)
		String fcstUrl = UriComponentsBuilder
				.fromHttpUrl("https://apis.data.go.kr/1360000/VilageFcstInfoService_2.0/getUltraSrtFcst")
				.queryParam("ServiceKey", serviceKey)
				.queryParam("dataType", "JSON")
				.queryParam("base_date", baseDate)
				.queryParam("base_time", "0800")
				.queryParam("nx", nx)
				.queryParam("ny", ny)
				.queryParam("numOfRows", 60)
				.build(false).toUriString();
		String fcstJson = weatherWebClient.get().uri(fcstUrl).retrieve().bodyToMono(String.class).block();
		
		
		// 파싱 및 병합
		Weather weather = parseWeather(ncstJson, fcstJson);
		
		return weather;
	}

	// 기상청에서 응답 받은 json을 자바 Weather Dto로 변환 해주는 함수
	private Weather parseWeather(String ncstJson, String fcstJson) {
		Weather weather = new Weather();
		try {
			ObjectMapper mapper = new ObjectMapper();
			
			// 실황 데이터 파싱
			JsonNode ncstItems = mapper.readTree(ncstJson).path("response").path("body").path("items").path("item");
			for (JsonNode item : ncstItems) {
				String category = item.get("category").asText();
				String value = item.get("obsrValue").asText();
				switch (category) {
					case "T1H" -> weather.setTemperature(value);
					case "REH" -> weather.setHumidity(value);
					case "PTY" -> weather.setRain(ptyCodeToDesc(value));
				}
			}

			// 예보 데이터 파싱 (SKY)
			JsonNode fcstItems = mapper.readTree(fcstJson).path("response").path("body").path("items").path("item");
			for (JsonNode item : fcstItems) {
				String category = item.get("category").asText();
				String value = item.get("fcstValue").asText();
				if ("SKY".equals(category)) {
					weather.setSky(skyCodeToDesc(value));
					break;
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return weather;
	}
	
	// 하늘 상태 파싱 
	private String skyCodeToDesc(String code) {
		return switch (code) {
			case "1" -> "맑음";
			case "3" -> "구름 많음";
			case "4" -> "흐림";
			default -> "정보 없음";
		};
	}

	// 강수 상태 케이스별로 파싱 
	private String ptyCodeToDesc(String code) {
		return switch (code) {
		case "1" -> "비";
		case "2" -> "비/눈";
		case "3" -> "눈";
		case "4" -> "소나기";
		default -> "없음";
		};
	}

}
