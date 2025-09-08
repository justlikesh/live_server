package com.ssafy.fitcha.model.service;

import org.springframework.stereotype.Service;

import com.ssafy.fitcha.model.dao.LikeDao;
import com.ssafy.fitcha.model.dto.Like;

@Service
public class LikeServiceImpl implements LikeService {

	private LikeDao likeDao;

	public LikeServiceImpl(LikeDao likeDao) {
		this.likeDao = likeDao;
	}

	// 로그인 유저의 챌린지 글 좋아요 여부 조회
	@Override
	public Like getChallengeLike(int challengeBoardId, String writer) {
		Like like = new Like();
		like.setBoardId(challengeBoardId);
		like.setWriter(writer);
		int likeCount = likeDao.selectChallengeLikeCount(challengeBoardId);
		int isLike = likeDao.selectUserChallengeLiked(like);
		like.setLikeCount(likeCount);
		like.setLike(isLike);
		return like;
	}

	// 로그인 유저의 챌린지 글 좋아요 상태 수정
	@Override
	public boolean updateChallengeLike(Like like) {

		// 좋아요 누르면 true
		if (like.getLike() == 1) {
			return 1 == likeDao.insertChallengeLike(like);
		}

		return 1 == likeDao.deleteChallengeLike(like);

	}

	// -------------------- 인증글 좋아요-------------------------------------------------

	// 로그인 유저의 인증글 좋아요 여부 조회
	@Override
	public boolean getProofLike(int proofBoardId, String nickName) {
		Like like = new Like();
		like.setBoardId(proofBoardId);
		like.setWriter(nickName);

		return null != likeDao.selectProofLike(like);
	}

	@Override
	public boolean addLike(int proofBoardId, String nickName) {
		Like like = new Like();
		like.setBoardId(proofBoardId);
		like.setWriter(nickName);
		return likeDao.insertProofLike(like) == 1;
	}

	@Override
	public boolean removeLike(int proofBoardId, String nickName) {
		Like like = new Like();
		like.setBoardId(proofBoardId);
		like.setWriter(nickName);
		return likeDao.deleteProofLike(like) == 1;
	}

	@Override
	public boolean checkLikeByWriter(int proofBoardId, String writer) {
		Like like = new Like();
		like.setBoardId(proofBoardId);
		like.setWriter(writer);
		return likeDao.selecCheckProofLike(like) > 0;
	}

	// -------------------- 영상 좋아요-------------------------------------------------

	@Override
	public boolean updateVideoLike(Like like) {

		// 좋아요 누르면 true
		if (like.getLike() == 1) {
			return 1 == likeDao.insertVideoLike(like);
		}

		return 1 == likeDao.deleteVideoLike(like);

	}

	// 좋아요 여부 및 좋아요 수 조회
	@Override
	public Like getVideoLike(String videoId, String writer) {
		Like like = new Like();
		like.setVideoId(videoId);
		like.setWriter(writer);
		int likeCount = likeDao.selectVideoLikeCount(videoId);
		int isLike = likeDao.selectUserVideoLiked(like);
		like.setLikeCount(likeCount);
		like.setLike(isLike);

		return like;

	}

}
