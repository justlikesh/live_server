package com.ssafy.fitcha.model.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description="인증글 댓글 DTO")
public class CommentProof {
	private int proofCommentId;
	private int proofBoardId ;
	private String userId;
	private String 	content;
	private String writer ;
	private String regDate;
	
	
	


	public CommentProof() {
	}
	public int getProofCommentId() {
		return proofCommentId;
	}
	public void setProofCommentId(int proofCommentId) {
		this.proofCommentId = proofCommentId;
	}
	public int getProofBoardId() {
		return proofBoardId;
	}
	public void setProofBoardId(int proofBoardId) {
		this.proofBoardId = proofBoardId;
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
