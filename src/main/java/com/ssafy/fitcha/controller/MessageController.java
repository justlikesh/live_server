package com.ssafy.fitcha.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.ssafy.fitcha.model.dto.Message;
import com.ssafy.fitcha.model.dto.User;
import com.ssafy.fitcha.model.service.MessageService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpSession;

@RestController
@RequestMapping("/message")
@Tag(name="Message RESTful API")
public class MessageController {
	@Autowired
	private MessageService messageService;

	@GetMapping
	@Operation(summary="유저의 메세지 목록 전체 조회")
	public ResponseEntity<List<Message>> getMessages(HttpSession session) {
		List<Message> messages = null;
		try {
			User user =(User) session.getAttribute("loginUser");
			messages = messageService.getMessages(user.getNickName());

			if (messages == null || messages.isEmpty()) {
				return ResponseEntity.noContent().build();
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return ResponseEntity.ok(messages);
	}

	@Operation(summary="다른 유저에 메세지 보내기")
	@PostMapping
	public ResponseEntity<Void> sendMessage(@RequestBody Message message) {
		if (messageService.sendMessage(message))
			return ResponseEntity.status(HttpStatus.CREATED).build();
		else
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();

	}
	
	@Operation(summary="메세지 삭제", description="현재 유저의 화면에서 메세지가 삭제되며 보낸이와 받는이 모두 삭제요청시 DB에서 삭제")
	@DeleteMapping()
	public ResponseEntity<Void> deleteMessage(@ModelAttribute Message message){
		
		if (messageService.deleteMessage(message))
			return ResponseEntity.status(HttpStatus.CREATED).build();
		else
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
	}
	

	

}
