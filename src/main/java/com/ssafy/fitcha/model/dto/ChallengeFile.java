package com.ssafy.fitcha.model.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description="챌린지 게시글 파일 DTO")
public class ChallengeFile {
	private int challengeFileId;
	private int challengeBoardId;
	private String fileUploadName;
	private String fileOriginalName;
	private String fileUrl;

	public String getFileUploadName() {
		return fileUploadName;
	}

	public void setFileUploadName(String fileUploadName) {
		this.fileUploadName = fileUploadName;
	}

	private String writer;

	public int getChallengeFileId() {
		return challengeFileId;
	}

	public void setChallengeFileId(int challengeFileId) {
		this.challengeFileId = challengeFileId;
	}

	public int getChallengeBoardId() {
		return challengeBoardId;
	}

	public void setChallengeBoardId(int challengeBoardId) {
		this.challengeBoardId = challengeBoardId;
	}

	public String getFileOriginalName() {
		return fileOriginalName;
	}

	public void setFileOriginalName(String fileOriginalName) {
		this.fileOriginalName = fileOriginalName;
	}

	public String getFileUrl() {
		return fileUrl;
	}

	public void setFileUrl(String fileUrl) {
		this.fileUrl = fileUrl;
	}

	public String getWriter() {
		return writer;
	}

	public void setWriter(String writer) {
		this.writer = writer;
	}

}
