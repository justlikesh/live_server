package com.ssafy.fitcha.controller;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.ssafy.fitcha.model.dto.User;
import com.ssafy.fitcha.model.service.FileService;
import com.ssafy.fitcha.model.service.UserService;
import com.ssafy.fitcha.util.JwtUtil;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpSession;

@RestController
@RequestMapping("/user")
@Tag(name = "User RESTful API", description = "사용자의 회원가입, 로그인, 로그아웃, 팔로우 기능")
public class UserController {

	@Autowired
	private JwtUtil jwtUtil;

	// 생성자 의존성 주입
	private final UserService userService;
	private final FileService fileService;

	public UserController(UserService userService, FileService fileService) {
		this.userService = userService;
		this.fileService = fileService;
	}

	@Operation(summary = "로그인/로그아웃 상태 변경", description = "서버의 세션 상태를 바꿈. 이런 상태 변화가 있는 작업은 POST 또는 DELETE로 처리하는 것이 REST 관점")
	@PostMapping("/login")
	public ResponseEntity<?> login(@RequestBody User user) {

		// 로그인 요청 받은 id와 DB에 등록된 동일한 id를 가진 유저를 반환
		User registedUser = userService.login(user);

		// null이라면 로그인 요청 받은 id와 동일한 user가 없다는 것 -> 아이디 존재 X
		if (registedUser == null) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("아이디가 존재하지 않습니다.");
		}

		// 아이디는 동일하지만 패스워드가 일치하지 않는 경우
		if (!user.getPassword().equals(registedUser.getPassword())) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("비밀번호가 일치하지 않습니다.");
		}

		// 아이디와 패스워드 일치 -> 로그인 성공
		// JWT 발급
		String token = jwtUtil.createToken(String.valueOf(registedUser.getUserBoardId()));
		// 응답에 토큰, 유저 아이디, 닉네임 같이 넣기
		Map<String, Object> responseBody = new HashMap<>();
		responseBody.put("token", token);
		responseBody.put("userId", registedUser.getUserId());
		responseBody.put("nickName", registedUser.getNickName());
		responseBody.put("userBoardId", registedUser.getUserBoardId());
		responseBody.put("profileImgUrl", registedUser.getProfileImgUrl());

		return ResponseEntity.ok().header("Authorization", "Bearer " + token).body(responseBody);
	}

	@Operation(summary = "로그아웃")
	@PostMapping("/logout")
	public ResponseEntity<?> logout(HttpSession session) {
		session.invalidate(); // 세션 무효화 -> 로그아웃
		return ResponseEntity.ok("로그아웃 되었습니다.");
	}

	@Operation(summary = "사용자 회원가입(등록)")
	@PostMapping("/signup")
	public ResponseEntity<Void> registUser(@RequestBody User user) {

		System.out.println(user.getNickName());

		if (userService.registUser(user)) {

			return ResponseEntity.ok().build();
		}
		return ResponseEntity.badRequest().build();
	}

	@Operation(summary = "사용자 탈퇴(삭제)")
	@DeleteMapping("/{userBoardId}")
	public ResponseEntity<Void> deleteUser(@PathVariable("userBoardId") int userBoardId) {

		if (userService.deleteUser(userBoardId)) {
			return ResponseEntity.ok().build();
		}

		return ResponseEntity.badRequest().build();
	}

	@Operation(summary = "다른 사용자 팔로우 등록")
	@PostMapping("/follow")
	public ResponseEntity<Void> followUser(@RequestParam String followerNickName,
			@RequestParam String followingNickName) {
		if (userService.follow(followerNickName, followingNickName)) {
			return ResponseEntity.ok().build();
		}
		return ResponseEntity.badRequest().build();
	}

	@Operation(summary = "다른 사용자 팔로잉 취소")
	@DeleteMapping("/follow")
	public ResponseEntity<Void> unfollowUser(@RequestParam String followerNickName,
			@RequestParam String followingNickName) {
		if (userService.unfollow(followerNickName, followingNickName)) {
			return ResponseEntity.ok().build();
		}
		return ResponseEntity.badRequest().build();
	}

	@Operation(summary = "사용자의 팔로워 및 팔로잉 수 조회")
	@GetMapping("/follow/{targetNickName}")
	public ResponseEntity<Map<String, Integer>> getFollowCount(@PathVariable("targetNickName") String nickName) {

		Map<String, Integer> followCount = new HashMap<>(); // 맵 형태로 팔로워 수, 팔로잉 수 저장
		followCount = userService.getFollowAllCount(nickName);

		if (followCount != null) {
			return ResponseEntity.ok(followCount);
		}

		return ResponseEntity.badRequest().build();

	}

	@Operation(summary = "상대방을 팔로우하고 있는지 여부를 반환")
	@GetMapping("/follow/check/{nickName}/{followingNickName}")
	public ResponseEntity<Boolean> checkFollowing(
	    @PathVariable("nickName") String followerNickName,
	    @PathVariable("followingNickName") String followingNickName // ✅ 일치시킴
	) {
	    System.out.println("followerNickName: " + followerNickName);
	    System.out.println("followingNickName: " + followingNickName);
	    boolean isFollowing = userService.isFollowing(followerNickName, followingNickName);
	    return ResponseEntity.ok(isFollowing);
	}

	
	@Operation(summary = "사용자의 팔로워 전체 목록 조회")
	@GetMapping("/follow/{userNickName}/follower")
	public ResponseEntity<List<String>> getFollowerAll(@PathVariable("userNickName") String userNickName) {
		List<String> followerAllList = new ArrayList<>();
		followerAllList = userService.getFollowerAllList(userNickName);

		if (followerAllList != null) {
			return ResponseEntity.ok(followerAllList);
		}
		return ResponseEntity.badRequest().build();

	}

	@Operation(summary = "사용자의 팔로잉 전체 목록 조회")
	@GetMapping("/follow/{userNickName}/following")
	public ResponseEntity<List<String>> getFollowingAll(@PathVariable("userNickName") String userNickName) {
		List<String> followingAllList = new ArrayList<>();
		followingAllList = userService.getFollowingAllList(userNickName);

		if (followingAllList != null) {
			return ResponseEntity.ok(followingAllList);
		}
		return ResponseEntity.badRequest().build();

	}

	@Operation(summary = "유저 정보 조회")
	@GetMapping("/{userNickName}")
	public ResponseEntity<User> getUserInfo(@PathVariable("userNickName") String userNickName) {
		User selectedUser = userService.getUserInfo(userNickName);

		if (selectedUser != null) {
			return ResponseEntity.ok(selectedUser);
		}
		return ResponseEntity.badRequest().build();
	}

	@Operation(summary = "프로필 이미지 수정")
	@PutMapping("/update/{userBoardId}")
	public ResponseEntity<User> updateUserInfo(@PathVariable int userBoardId, @RequestParam("nickName") String nickName,
			@RequestParam(value = "profileImgUrl", required = false) MultipartFile profileImgUrl) {

		User user = new User();
		user.setUserBoardId(Integer.valueOf(userBoardId));
		user.setNickName(nickName);

		try {
			if (profileImgUrl != null && !profileImgUrl.isEmpty()) {
				String imageUrl = fileService.updateUserFile(profileImgUrl);
				user.setProfileImgUrl(imageUrl);
			}
		} catch (IOException e) {
			e.printStackTrace();
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
		}

		if (userService.updateUserInfo(user)) {
			User updatedUser = userService.getUserInfo(nickName);
			return ResponseEntity.ok(updatedUser);
		}

		return ResponseEntity.badRequest().build();

	}

}