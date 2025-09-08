package com.ssafy.fitcha.model.dto;


public class BoardFile {
	private int FileId;
	private int BoardId;
	private String fileUploadName;
	public int getFileId() {
		return FileId;
	}
	public void setFileId(int fileId) {
		FileId = fileId;
	}
	public int getBoardId() {
		return BoardId;
	}
	public void setBoardId(int boardId) {
		BoardId = boardId;
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
	private String fileOriginalName;
	private String fileUrl;

	

}
