package com.ssafy.fitcha.model.service;

import java.util.List;

import org.springframework.stereotype.Service;

import com.ssafy.fitcha.model.dao.CommentDao;
import com.ssafy.fitcha.model.dto.Comment;
import com.ssafy.fitcha.model.dto.CommentProof;

@Service
public class CommentServiceImpl implements CommentService {
	private CommentDao commentDao;

	public CommentServiceImpl(CommentDao commentDao) {
		this.commentDao = commentDao;
	}

	// 챌린지 댓글 조회
	@Override
	public List<Comment> getChallengeCommentList(int challengeBoardId) {
		return commentDao.selectChallengeCommentList(challengeBoardId);

	}

	// 챌린지 댓글 등록
	@Override
	public boolean registChallengeComment( Comment comment) {
		return 1 == commentDao.insertChallengeComment(comment);

	}

	// 챌린지 글의 댓글 삭제
	@Override
	public boolean deleteChallengeComment(int challengeBoardId, int challengeCommentId) {
		Comment comment = new Comment();
		comment.setChallengeBoardId(challengeBoardId);
		comment.setChallengeCommentId(challengeCommentId);
		return 1 == commentDao.deleteChallengeComment(comment);

	}

	// 챌린지 글의 댓글 수정
	@Override
	public boolean updateChallengeComment(int challengeBoardId, int challengeCommentId, Comment comment) {
		comment.setChallengeBoardId(challengeBoardId);
		comment.setChallengeCommentId(challengeCommentId);
		return 1 == commentDao.updateChallengeComment(comment);
	}
	
	// ------------------------------- 인증글 댓글 -----------------------------------------------------
	
	
	// 인증글 댓글 목록 조회 
	@Override
	public List<CommentProof> getProofCommentList(int proofBoardId) {
		return commentDao.selectProofCommentList(proofBoardId);
	}
	
	// 인증글 댓글 등록
	@Override
	public boolean registProofComment(int proofBoardId, CommentProof comment) {
		comment.setProofBoardId(proofBoardId);
		return 1 == commentDao.insertProofComment(comment);
	}
	
	// 인증글 댓글 삭제 
	@Override
	public boolean deleteProofComment(int proofBoardId, int proofCommentId) {
		CommentProof comment = new CommentProof();
		comment.setProofBoardId(proofBoardId);
		comment.setProofCommentId(proofCommentId);
		return 1 == commentDao.deleteProofComment(comment);
	}
	
	// 인증글 댓글 수정 
	@Override
	public boolean updateProofComment(int proofBoardId, int proofCommentId, CommentProof comment) {
		comment.setProofBoardId(proofBoardId);
		comment.setProofCommentId(proofCommentId);
		return 1 == commentDao.updateProofComment(comment);
	}
	
	//-------------------- 영상 댓글 ---------------------

	//영상 댓글 목록 조회 
	@Override
	public List<Comment> getVideoCommentList(String videoId) {
		return commentDao.selectVideoCommentList(videoId);

	}

	//영상 댓글 등록 
	@Override
	public boolean registVideoComment(Comment comment) {
		return 1 == commentDao.insertVideoComment(comment);

	}

	//영상 댓글 삭제
	@Override
	public boolean deleteVideoComment(String videoId, int videoCommentId) {
		
		Comment comment = new Comment();
		comment.setVideoId(videoId);
		comment.setCommentId(videoCommentId);
		return 1 == commentDao.deleteVideoComment(comment);
	}

	@Override
	public boolean updateVideoComment(Comment comment) {
		return 1 == commentDao.updateVideoComment(comment);
	}

}
