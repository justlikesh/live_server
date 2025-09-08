package com.ssafy.fitcha.model.service;

import java.util.List;

import com.ssafy.fitcha.model.dto.Message;

public interface MessageService {

	//전체 조회
	List<Message> getMessages(String userNickname);
	
	//메세지 보내기
	boolean sendMessage(Message message);
	
	//삭제
	boolean deleteMessage(Message message);

}
