package com.ssafy.fitcha.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.ssafy.fitcha.model.service.NicknameService;

@RestController
@RequestMapping("/api/nickname")
public class NicknameController {

	private NicknameService nicknameService;

	public NicknameController(NicknameService nicknameService) {
		this.nicknameService = nicknameService;
	}

	@GetMapping("/generate")
	public ResponseEntity<String> generateNickname() {
		String nickname = nicknameService.generateUniqueNickname();
		return ResponseEntity.ok(nickname);
	}

	@GetMapping("/check")
	public ResponseEntity<Boolean> checkDuplicate(@RequestParam String nickname) {
		boolean exists = nicknameService.isDuplicate(nickname);
		return ResponseEntity.ok(exists);
	}
}