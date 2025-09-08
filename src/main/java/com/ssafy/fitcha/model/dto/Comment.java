package com.ssafy.fitcha.model.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description="챌린지 댓글 DTO")
public class Comment {
	private int commentId;
	private int boardId ;
	private String userId;
	private String 	content;
	private String writer ;
	private String regDate;
	
	private int challengeCommentId;
	private int challengeBoardId;
	
	private String VideoId;
	
	
	
	public String getVideoId() {
		return VideoId;
	}
	public void setVideoId(String videoId) {
		VideoId = videoId;
	}
	public int getChallengeCommentId() {
		return challengeCommentId;
	}
	public void setChallengeCommentId(int challengeCommentId) {
		this.challengeCommentId = challengeCommentId;
	}
	public int getChallengeBoardId() {
		return challengeBoardId;
	}
	public void setChallengeBoardId(int challengeBoardId) {
		this.challengeBoardId = challengeBoardId;
	}
	public int getCommentId() {
		return commentId;
	}
	public void setCommentId(int commentId) {
		this.commentId = commentId;
	}
	public int getBoardId() {
		return boardId;
	}
	public void setBoardId(int boardId) {
		this.boardId = boardId;
	}
	public String getUserId() {
		return userId;
	}
	public void setUserId(String userId) {
		this.userId = userId;
	}
	public String getContent() {
		return content;
	}
	public void setContent(String content) {
		this.content = content;
	}
	public String getWriter() {
		return writer;
	}
	public void setWriter(String writer) {
		this.writer = writer;
	}
	public String getRegDate() {
		return regDate;
	}
	public void setRegDate(String regDate) {
		this.regDate = regDate;
	}

}
