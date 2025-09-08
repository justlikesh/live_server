package com.ssafy.fitcha.controller;

import java.time.LocalDateTime;

import org.springframework.messaging.handler.annotation.DestinationVariable;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Controller;

import com.ssafy.fitcha.model.dto.ChatMessage;
import com.ssafy.fitcha.model.dto.ChatMessageDto;
import com.ssafy.fitcha.model.service.ChatService;

//2. WebSocket 전용
@Controller
public class ChatWebSocketController {

	private final SimpMessagingTemplate messagingTemplate;
	private final ChatService chatService; // 메시지 저장용

	public ChatWebSocketController(SimpMessagingTemplate tpl, ChatService svc) {
		this.messagingTemplate = tpl;
		this.chatService = svc;
	}

	// 클라이언트가 /app/chat/{roomId} 로 publish 하면 이 메서드가 호출됩니다
	@MessageMapping("/chat/{roomId}")
	public void handleMessage(@DestinationVariable Long roomId, ChatMessageDto dto) {
		// 1) DB에 저장
		ChatMessage msg = new ChatMessage();
		msg.setRoomId(roomId);
		msg.setSender(dto.getSender());
		msg.setMessage(dto.getMessage());
		msg.setTimestamp(LocalDateTime.now());
		chatService.sendMessage(msg);

		// 2) 구독자들에게 브로드캐스트
		messagingTemplate.convertAndSend("/topic/chat/" + roomId, msg);
	}
}
