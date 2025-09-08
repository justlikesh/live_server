package com.ssafy.fitcha.model.dao;

import com.ssafy.fitcha.model.dto.Like;

public interface LikeDao {

	// 챌린지글 좋아요 등록
	int insertChallengeLike(Like like);

	// 챌린지글 좋아요 취소
	int deleteChallengeLike(Like like);

	// 챌린지 좋아요 수 조회
	int selectChallengeLikeCount(int challengeBoardId);

	// 챌린지글 좋아요 여부.
	int selectUserChallengeLiked(Like like);

	// --------------------------------------------------------------------------

	// 로그인 유저의 인증글 좋아요 여부.
	Like selectProofLike(Like like);

	// 로그인 유저의 인증글 좋아요 등록
	int insertProofLike(Like like);

	// 로그인 유저의 인증글 글 좋아요 취소
	int deleteProofLike(Like like);
	
	// 로그인 유저의 인증글 좋아요 체크 
	int selecCheckProofLike(Like like);
	

	// --------------------------------------------------------------------------

	// --------------------------------------------------------------------------

	// 영상 좋아요 등록
	int insertVideoLike(Like like);

	// 영상 좋아요 취소
	int deleteVideoLike(Like like);

	// 영상 좋아요 수 조회
	int selectVideoLikeCount(String videoId);

	// 영상 좋아요 여부 조회
	int selectUserVideoLiked(Like like);
	


	

}
