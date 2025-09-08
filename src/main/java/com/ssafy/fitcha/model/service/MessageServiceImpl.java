package com.ssafy.fitcha.model.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.ssafy.fitcha.model.dao.MessageDao;
import com.ssafy.fitcha.model.dto.Message;

@Service
public class MessageServiceImpl implements MessageService {
	@Autowired
	private MessageDao messageDao;

	@Override
	public List<Message> getMessages(String userNickname) {
		return messageDao.selectMessages(userNickname);
	}

	@Override
	public boolean sendMessage(Message message) {

		return messageDao.insertMessage(message) == 1;
	}

	@Override
	public boolean deleteMessage(Message message) {

		if (messageDao.deleteMessage(message) == 1)
			return true;
		else {
			return messageDao.updateMessage(message) == 1;
		}
	}

}
