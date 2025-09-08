package com.ssafy.fitcha.model.service;

import java.util.List;
import java.util.Map;

import org.springframework.web.multipart.MultipartFile;

import com.ssafy.fitcha.model.dto.Challenge;
import com.ssafy.fitcha.model.dto.SearchChallenge;

public interface ChallengeService {

	// 검색 목록 조회 (검색어 없을 시 전체 조회)
	List<Challenge> getSearchChallenges(SearchChallenge search) throws Exception;

	// 상세 정보
	Challenge getChallengeDetail(int challengeBoardId, String nickName, String isViewCounted);

	// 수정
	boolean updateChallenge(Challenge challenge, List<MultipartFile> files, List<Integer> deleteChallengeFileIds)
			throws Exception;

	// 삭제
	boolean deleteChallenge(int challengeBoardId, String writer);

	// 등록
	boolean registChallenge(Challenge challenge, List<MultipartFile> files) throws Exception;

	// top10 챌린지 목록
	List<Challenge> getTop10Challenges(String orderBy);

	// 챌린지 참여 등록
	boolean registChallengeParticipate(Challenge challenge);

	// 챌린지 참여 취소
	boolean deleteChallengeParticipate(int challengeBoardId, String writer);

	// 유저가 참여한 챌린지 조회 (마이핏 페이지)
	List<Challenge> getChallengeByNickName(String userNickName);

	// 챌린지 참여율 높은 top5 유저 조회
	List<Map<String, Object>> getTop5Challengers();

}
