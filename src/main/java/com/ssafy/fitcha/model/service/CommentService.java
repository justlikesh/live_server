package com.ssafy.fitcha.model.service;

import java.util.List;

import com.ssafy.fitcha.model.dto.Comment;
import com.ssafy.fitcha.model.dto.CommentProof;
import com.ssafy.fitcha.model.dto.User;

public interface CommentService {

	// 챌린지 댓글 조회
	List<Comment> getChallengeCommentList(int challengeBoardId);

	// 챌린지 댓글 등록
	boolean registChallengeComment( Comment comment);

	// 챌린지 댓글 삭제
	boolean deleteChallengeComment(int challengeBoardId, int challengeCommentId);

	// 챌린지 댓글 수정
	public boolean updateChallengeComment(int challengeBoardId, int challengeCommentId, Comment comment);

	// 인증글 댓글 조회
	List<CommentProof> getProofCommentList(int proofBoardId);

	// 인증글 댓글 등록
	boolean registProofComment(int proofBoardId, CommentProof comment);

	// 인증글 댓글 삭제
	boolean deleteProofComment(int proofBoardId, int proofCommentId);

	// 인증글 댓글 수정
	boolean updateProofComment(int proofBoardId, int proofCommentId, CommentProof comment);

	//영상 댓글 조회 
	List<Comment> getVideoCommentList(String videoId);

	//영상 댓글 등록
	boolean registVideoComment(Comment comment);

	//영상 댓글 삭제 
	boolean deleteVideoComment(String videoId, int videoCommentId);

	//영상 댓글 수정
	boolean updateVideoComment(Comment comment);
}
