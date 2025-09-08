package com.ssafy.fitcha.model.dao;

import java.util.List;

import com.ssafy.fitcha.model.dto.Comment;
import com.ssafy.fitcha.model.dto.CommentProof;

public interface CommentDao {

	//챌린지 댓글 삭제
	int deleteChallengeComment(Comment comment);

	//챌린지 댓글목록 조회 
	List<Comment> selectChallengeCommentList(int challengeBoardId);

	//챌린지 댓글 등록 
	int insertChallengeComment(Comment comment);

	//챌린지 댓글 수정
	int updateChallengeComment(Comment comment);

	// ---------------------------------인증글 댓글----------------------------------------------------------
	
	// 인증글 댓글 목록 조회 
	List<CommentProof> selectProofCommentList(int proofBoardId);
	
	// 인증글 댓글 등록
	int insertProofComment(CommentProof comment);
	
	// 인증글 댓글 삭제
	int deleteProofComment(CommentProof comment);

	// 인증글 댓글 수정 
	int updateProofComment(CommentProof comment);
	
	
	// --------------------------------- 영상 댓글----------------------------------------------------------

	//영상 댓글 목록 조회
	List<Comment> selectVideoCommentList(String videoId);

	//영상 댓글 등록
	int insertVideoComment(Comment comment);

	//영상 댓글 삭제
	int deleteVideoComment(Comment comment);

	//영상 댓글 수정
	int updateVideoComment(Comment comment);

}
