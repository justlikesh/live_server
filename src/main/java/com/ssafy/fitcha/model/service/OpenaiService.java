package com.ssafy.fitcha.model.service;

import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

// @Service
public class OpenaiService {

	@Value("${openai.api.key}")
	private String openaiApiKey;

	public String getSubheadFromGPT(String title, String content) {
		String prompt = String.format("""
				%s 라는 제목의 운동 챌린지가 있어.
				챌린지의 내용은 "%s"야.
				제목과 내용을 고려해서 소제목을 하나만 추천해줘.
				소제목의 길이는 무조건 25자에서 32자로 꼭 맞춰줘.
				그리고 마지막 단어는 챌린지, 습관, 도전, 루틴, 건강과 같이 운동에 어울리는 단어로 작성해줘.
				답변을 할때는 한줄로 말하고, -나 "는 사용하지 마
				""", title, content);

		RestTemplate restTemplate = new RestTemplate();

		// 메시지 구성
		Map<String, Object> message = Map.of("role", "user", "content", prompt);
		Map<String, Object> requestBody = Map.of("model", "gpt-3.5-turbo", "messages", List.of(message));

		// 헤더 설정
		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_JSON);
		headers.setBearerAuth(openaiApiKey); // OpenAI API 키

		// 요청 보내기
		HttpEntity<Map<String, Object>> requestEntity = new HttpEntity<>(requestBody, headers);
		ResponseEntity<Map> response = restTemplate.postForEntity("https://api.openai.com/v1/chat/completions",
				requestEntity, Map.class);

		// 응답에서 content만 꺼내기
		List choices = (List) response.getBody().get("choices");
		Map firstChoice = (Map) choices.get(0);
		Map messageMap = (Map) firstChoice.get("message");
		return (String) messageMap.get("content"); // 👉 이게 바로 '소제목'
	}

}
