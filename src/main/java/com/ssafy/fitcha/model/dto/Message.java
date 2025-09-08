package com.ssafy.fitcha.model.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description="메세지 DTO")
public class Message {
	private int messageId; //쪽지 고유 번호.
	private String sender; // 보낸 사람.
	private String recipient; //받는 사람.
	private String title; //제목
	private String content; //내용
	private String whoDelete; //nobody, sender,recipient로 아무도 삭제 안함., 보낸사람이 삭제원함., 받는사람이 삭제원함.
	private boolean isRead; // 읽음 여부.
	public int getMessageId() {
		return messageId;
	}
	public void setMessageId(int messageId) {
		this.messageId = messageId;
	}
	public String getSender() {
		return sender;
	}
	public void setSender(String sender) {
		this.sender = sender;
	}
	public String getRecipient() {
		return recipient;
	}
	public void setRecipient(String recipient) {
		this.recipient = recipient;
	}
	public String getTitle() {
		return title;
	}
	public void setTitle(String title) {
		this.title = title;
	}
	public String getContent() {
		return content;
	}
	public void setContent(String content) {
		this.content = content;
	}
	public String getWhoDelete() {
		return whoDelete;
	}
	public void setWhoDelete(String whoDelete) {
		this.whoDelete = whoDelete;
	}
	public boolean isRead() {
		return isRead;
	}
	public void setRead(boolean isRead) {
		this.isRead = isRead;
	}

	
	
	
	
}
