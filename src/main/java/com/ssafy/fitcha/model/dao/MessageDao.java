package com.ssafy.fitcha.model.dao;

import java.util.List;

import com.ssafy.fitcha.model.dto.Message;

public interface MessageDao {
	
	//전체 메세지 조회.
	List<Message> selectMessages(String userNickname);

	//메세지 보내기.
	int insertMessage(Message message);

	//메세지 삭제
	int deleteMessage(Message message);

	// 삭제 여부 수정.
	int updateMessage(Message message);
}
