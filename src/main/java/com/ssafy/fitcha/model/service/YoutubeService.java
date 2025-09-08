package com.ssafy.fitcha.model.service;

import java.util.List;
import java.util.Map;

import com.ssafy.fitcha.model.dto.Youtube;

public interface YoutubeService {

	// 필터 적용(검색)시 유튜브 목록 조회
//	List<Youtube> getSearchVideos(String query);
//	Map<String, Object>getSearchVideos(String query);

	Map<String, Object> getSearchVideos(String query, String pageToken);

	Map<String, Object> getVideo(String videoId);
}
