package com.ssafy.fitcha.model.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description="인증 게시글 파일 DTO")

public class ProofFile {
	private int proofFileId; // 인증글의 파일 식별을 위한 id
	private int proofBoardId; // 인증글 식별 id
	private String fileUploadName; // 파일 업로드 이름
	private String fileOriginalName; // 파일 원래 이름
	private String fileUrl; // 파일 url
	private String writer; // 작성자 닉네임

	// 생성자
	public ProofFile() {
	}

	// getter / setter
	public int getProofFileId() {
		return proofFileId;
	}

	public void setProofFileId(int proofFileId) {
		this.proofFileId = proofFileId;
	}

	public int getProofBoardId() {
		return proofBoardId;
	}

	public void setProofBoardId(int proofBoardId) {
		this.proofBoardId = proofBoardId;
	}

	public String getFileUploadName() {
		return fileUploadName;
	}

	public void setFileUploadName(String fileUploadName) {
		this.fileUploadName = fileUploadName;
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
