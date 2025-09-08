package com.ssafy.fitcha.controller;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.ssafy.fitcha.model.dto.Challenge;
import com.ssafy.fitcha.model.service.ChallengeService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;

@RestController
@Tag(name = "Main RESTful API")
public class MainController {
	private final ChallengeService challengeService;

	public MainController(ChallengeService challengeService) {
		this.challengeService = challengeService;
	}

	@GetMapping({ "/home", "/" })
	@Operation(summary = "메인화면 요소", description = "메인화면에 보여줄 챌린지 게시글 정보 조회")
	public ResponseEntity<Map<String, List<Object>>> main() {
		Map mainMap = new HashMap<>();
		List<Challenge> recentChallenges = challengeService.getTop10Challenges("recent"); // 최근 등록한 챌린지 게시글
		List<Challenge> manyParticipantsChallenges = challengeService.getTop10Challenges("participants");// 참여자 많은 챌린지
																											// 게시글
		List<Challenge> manyLikesChallenges = challengeService.getTop10Challenges("likes"); // 좋아요수 많은 챌린지 게시글
		List<Challenge> manyViewsiewsChallenges = challengeService.getTop10Challenges("views"); // 조회수 많은 챌린지 게시글
		mainMap.put("recent", recentChallenges);
		mainMap.put("participants", manyParticipantsChallenges);
		mainMap.put("likes", manyLikesChallenges);
		mainMap.put("views", manyViewsiewsChallenges);

		return ResponseEntity.ok(mainMap);
	}

}
