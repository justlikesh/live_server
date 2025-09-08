package com.ssafy.fitcha.model.service;

import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import com.ssafy.fitcha.model.dto.Youtube;

// @Service
public class YoutubeServiceImpl implements YoutubeService {

	@Value("${youtube.api.key}")
	private String apiKey;

	private final String YOUTUBE_SEARCH_URL = "https://www.googleapis.com/youtube/v3/search";
	private final String YOUTUBE_VIDEO_URL = "https://www.googleapis.com/youtube/v3/videos";

	@Override
	public Map<String, Object> getSearchVideos(String query, String pageToken) {
	    RestTemplate restTemplate = new RestTemplate();

	    UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(YOUTUBE_SEARCH_URL)
	            .queryParam("part", "snippet")
	            .queryParam("q", query)
	            .queryParam("key", apiKey)
	            .queryParam("type", "video")
	            .queryParam("videoDuration", "long")
	            .queryParam("maxResults", 10);

	    if (pageToken != null && !pageToken.isEmpty()) {
	        builder.queryParam("pageToken", pageToken);
	    }

	    String searchUrl = builder.build().toUriString();
	    return restTemplate.getForObject(searchUrl, Map.class);
	}
	@Override
	public Map<String, Object> getVideo(String videoId) {
	    RestTemplate restTemplate = new RestTemplate();

	    UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(YOUTUBE_VIDEO_URL)
	            .queryParam("part", "snippet,contentDetails")
	            .queryParam("id", videoId)
	            .queryParam("key", apiKey);
	    
	    String searchUrl = builder.build().toUriString();
	    return restTemplate.getForObject(searchUrl, Map.class);
	}
	

}