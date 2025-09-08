package com.ssafy.fitcha.controller;

import java.net.URI;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.ssafy.fitcha.model.dto.ChatMessage;
import com.ssafy.fitcha.model.dto.ChatRoom;
import com.ssafy.fitcha.model.dto.SearchChallenge;
import com.ssafy.fitcha.model.service.ChatService;

import io.swagger.v3.oas.annotations.Operation;

@RestController
@RequestMapping("/api/chat")
public class ChatRestController {
	@Autowired
	private ChatService chatService;
	@Autowired
	private SimpMessagingTemplate messagingTemplate;

	@GetMapping("/rooms")
	public ResponseEntity<List<ChatRoom>> getRooms(@ModelAttribute SearchChallenge search) {
		List<ChatRoom> chatrooms = null;
		try {
			chatrooms = chatService.getRooms(search);

			if (chatrooms == null || chatrooms.isEmpty()) {
				return ResponseEntity.noContent().build();
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return ResponseEntity.ok(chatrooms);

	}

	@PostMapping("/rooms")
	public void createRoom(@RequestBody ChatRoom room) {
		System.out.println(room.getWriter());
		chatService.createRoom(room);
	}

	@GetMapping("/rooms/{roomId}")
	public ChatRoom getRoom(@PathVariable Long roomId) {
		return chatService.getRoom(roomId);
	}

	@GetMapping("/messages/{roomId}")
	public List<ChatMessage> getMessages(@PathVariable Long roomId) {
		return chatService.getMessages(roomId);
	}

	@Operation(summary = "채팅방 삭제")
	@DeleteMapping("/{roomId}")
	public ResponseEntity<Void> deleteChallenge(@PathVariable("roomId") int roomId) {
		chatService.deleteRoom(roomId);

		URI redirectUri = URI.create("/challenge");
		return ResponseEntity.status(HttpStatus.SEE_OTHER).location(redirectUri).build();
	}

}
