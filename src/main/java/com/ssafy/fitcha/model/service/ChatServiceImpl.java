package com.ssafy.fitcha.model.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.ssafy.fitcha.model.dao.ChatDao;
import com.ssafy.fitcha.model.dto.ChatMessage;
import com.ssafy.fitcha.model.dto.ChatRoom;
import com.ssafy.fitcha.model.dto.SearchChallenge;

@Service
public class ChatServiceImpl implements ChatService {

	@Autowired
	private ChatDao chatDao;

	@Override
	public List<ChatRoom> getRooms(SearchChallenge search) {
		return chatDao.getRooms(search);
	}

	@Override
	public void createRoom(ChatRoom room) {
		// 예시: 같은 이름의 방이 이미 있으면 생성 안 함
		if (chatDao.findRoomByName(room.getName()) == null) {
			chatDao.createRoom(room);
		}
	}

	@Override
	public ChatRoom getRoom(Long roomId) {
		return chatDao.getRoom(roomId);
	}

	@Override
	public List<ChatMessage> getMessages(Long roomId) {
		return chatDao.getMessages(roomId);
	}

	@Override
	public void sendMessage(ChatMessage message) {
		chatDao.sendMessage(message);
	}

	@Override
	public void deleteRoom(int roomId) {
		chatDao.deleteRoom(roomId);

	}
}
