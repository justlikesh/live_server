package com.ssafy.fitcha.controller;

import java.net.URI;
import java.util.List;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.ssafy.fitcha.model.dto.Challenge;
import com.ssafy.fitcha.model.dto.Comment;
import com.ssafy.fitcha.model.dto.Like;
import com.ssafy.fitcha.model.dto.SearchChallenge;
import com.ssafy.fitcha.model.service.ChallengeService;
import com.ssafy.fitcha.model.service.CommentService;
import com.ssafy.fitcha.model.service.LikeService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;

@RestController
@RequestMapping("/challenge")
@Tag(name = "Challenge RESTfull API", description = "운동 챌린지 게시판 CRUD ")
public class ChallengeController {
	private ChallengeService challengeService;
	private CommentService commentService;
	private LikeService likeService;

	public ChallengeController(ChallengeService challengeService, CommentService commentService,
			LikeService likeService) {
		this.challengeService = challengeService;
		this.commentService = commentService;
		this.likeService = likeService;
	}

	@Operation(summary = "챌린지 게시글 검색 및 전체 목록 조회")
	@GetMapping
	public ResponseEntity<List<Challenge>> getSearchChallenges(@ModelAttribute SearchChallenge search) {
		List<Challenge> challenges = null;
		try {
			challenges = challengeService.getSearchChallenges(search);

			if (challenges == null || challenges.isEmpty()) {
				return ResponseEntity.noContent().build();
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return ResponseEntity.ok(challenges);
	}

	@Operation(summary = "챌린지 게시글 상세 조회")
	@GetMapping("/{challengeBoardId}")
	public ResponseEntity<Challenge> getDetailChallenge(@PathVariable("challengeBoardId") int challengeBoardId,
			@RequestParam("isViewCounted") String isViewCounted, @RequestParam("writer") String writer) {

		Challenge challenge = challengeService.getChallengeDetail(challengeBoardId, writer, isViewCounted);

		if (challenge == null)
			return ResponseEntity.noContent().build();
		return ResponseEntity.ok(challenge);
	}

	@Operation(summary = "챌린지 게시글 수정 ", description = "게시글 수정 후 상세화면으로 이동")
	@PutMapping("/{challengeBoardId}")
	public ResponseEntity<Integer> updateChallenge(@ModelAttribute Challenge challenge,
			@RequestParam(value = "files", required = false) List<MultipartFile> files, // 추가된 파일
			@RequestParam(value = "deleteChallengeFileIds", required = false) List<Integer> deleteChallengeFileIds // 삭제할

	// 파일
	) throws Exception {
		if (challengeService.updateChallenge(challenge, files, deleteChallengeFileIds))
			return ResponseEntity.ok(challenge.getChallengeBoardId());
		return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
	}

	@Operation(summary = "챌린지 게시글 삭제")
	@DeleteMapping("/{challengeBoardId}/{writer}")
	public ResponseEntity<Void> deleteChallenge(@PathVariable("challengeBoardId") int challengeBoardId,
			@PathVariable("writer") String writer) {
		challengeService.deleteChallenge(challengeBoardId, writer);

		URI redirectUri = URI.create("/challenge");
		return ResponseEntity.status(HttpStatus.SEE_OTHER).location(redirectUri).build();
	}

	@Operation(summary = "챌린지 게시글 등록")
	@PostMapping
	public ResponseEntity<Integer> registChallenge(
			@RequestParam(value = "files", required = false) List<MultipartFile> files,
			@ModelAttribute Challenge challenge) throws Exception {
		if (challengeService.registChallenge(challenge, files))
			return ResponseEntity.ok(challenge.getChallengeBoardId());

		return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();

	}

	@Operation(summary = "챌린지 참여 등록")
	@PostMapping(("/{challengeBoardId}/participate"))
	public ResponseEntity<Void> registChallengParticipate(@RequestBody Challenge challenge) throws Exception {

		if (challengeService.registChallengeParticipate(challenge))
			return ResponseEntity.ok().build();

		return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
	}

	@Operation(summary = "챌린지 참여 취소 ")
	@DeleteMapping(("/{challengeBoardId}/participate/{writer}"))
	public ResponseEntity<Void> registChallengParticipate(@PathVariable("challengeBoardId") int challengeBoardId,
			@PathVariable("writer") String writer) throws Exception {

		if (challengeService.deleteChallengeParticipate(challengeBoardId, writer))
			return ResponseEntity.ok().build();

		return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
	}

	@Operation(summary = "유저가 참여한 챌린지 조회")
	@GetMapping(("/participate/{nickName}"))
	public ResponseEntity<List<Challenge>> getChallengeByNickName(@PathVariable("nickName") String userNickName)
			throws Exception {
		List<Challenge> challenges = null;
		challenges = challengeService.getChallengeByNickName(userNickName);
		if (challenges != null) {
			return ResponseEntity.ok(challenges);
		}
		return ResponseEntity.badRequest().build();
	}

	// -------- 댓 글 ------------

	@Operation(summary = "챌린지 게시글의 전체 댓글 조회 ")
	@GetMapping("/{challengeBoardId}/comment")
	public ResponseEntity<List<Comment>> getChallengeComment(@PathVariable("challengeBoardId") int challengeBoardId) {
		List<Comment> comments = commentService.getChallengeCommentList(challengeBoardId);
		if (comments == null || comments.size() == 0) {
			return ResponseEntity.noContent().build();
		}
		return ResponseEntity.ok(comments);

	}

	@Operation(summary = "챌린지 게시글에 댓글 등록")
	@PostMapping("/{challengeBoardId}/comment")
	public ResponseEntity<Void> registChallengeComment(@RequestBody Comment comment) {

		if (commentService.registChallengeComment(comment)) {
			return ResponseEntity.status(HttpStatus.CREATED).build();
		}
		return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();

	}

	@Operation(summary = "챌린지 게시글의 댓글 삭제")
	@DeleteMapping("{challengeBoardId}/comment/{challengeCommentId}")
	public ResponseEntity<Void> deleteChallengeComment(@PathVariable("challengeBoardId") int challengeBoardId,
			@PathVariable("challengeCommentId") int challengeCommentId) {

		if (commentService.deleteChallengeComment(challengeBoardId, challengeCommentId)) {

			return ResponseEntity.ok().build();
		}
		return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();

	}

	@Operation(summary = "챌린지 게시글의 댓글 수정")
	@PutMapping("/{challengeBoardId}/comment/{challengeCommentId}")
	public ResponseEntity<Void> updateChallengeComment(@PathVariable("challengeBoardId") int challengeBoardId,
			@PathVariable("challengeCommentId") int challengeCommentId, @RequestBody Comment comment) {

		if (commentService.updateChallengeComment(challengeBoardId, challengeCommentId, comment)) {
			return ResponseEntity.ok(null);
		}

		return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();

	}

	// ----- 좋아요-----

	@Operation(summary = "챌린지 게시글 좋아요 수정 ")
	@PostMapping("/{challengeBoardId}/like")
	public ResponseEntity<Void> updateChallengeLike(@PathVariable("challengeBoardId") int challengeBoardId,
			@RequestBody Like like) {
		if (likeService.updateChallengeLike(like))
			return ResponseEntity.ok().build();
		return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();

	}

	@Operation(summary = "사용자의 챌린지 좋아요 여부 및 좋아요 수 조회")
	@GetMapping("/{challengeBoardId}/like/{writer}")
	public ResponseEntity<Like> getVideoLike(@PathVariable("challengeBoardId") int challengeBoardId,
			@PathVariable("writer") String writer) {
		Like like = likeService.getChallengeLike(challengeBoardId, writer);

		return ResponseEntity.ok(like);

	}

	@Operation(summary = "챌린지 참여율 높은 top5 유저 조회")
	@GetMapping("/top5")
	public ResponseEntity<List<Map<String, Object>>> getTop5Challengers() {
		List<Map<String, Object>> challengers = challengeService.getTop5Challengers();

		return ResponseEntity.ok(challengers);

	}

}