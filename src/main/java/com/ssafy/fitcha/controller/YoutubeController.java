package com.ssafy.fitcha.controller;

import java.util.List;
import java.util.Map;

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

import com.ssafy.fitcha.model.dto.Comment;
import com.ssafy.fitcha.model.dto.Like;
import com.ssafy.fitcha.model.service.CommentService;
import com.ssafy.fitcha.model.service.LikeService;
import com.ssafy.fitcha.model.service.YoutubeService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;

// @RestController
// @RequestMapping("/youtube")
@Tag(name = "Youtube API", description = "유튜브에 검색한 결과 정보 조회")
public class YoutubeController {
	private final YoutubeService youtubeService;
	private CommentService commentService;
	private LikeService likeService;

	public YoutubeController(YoutubeService youtubeService, CommentService commentService, LikeService likeService) {
		this.youtubeService = youtubeService;
		this.commentService = commentService;
		this.likeService = likeService;

	}

	@Operation(summary = "유튜브에 검색한 결과 정보 조회", description = "검색어가 없을 경우 '전신운동 홈트' 검색결과의 유튜브 정보를 가져옴.")
	@GetMapping("/search")
	public ResponseEntity<Map<String, Object>> getSearchVideos(
			@RequestParam(value = "query", defaultValue = "전신 운동 홈트") String query,
			@RequestParam(value = "pageToken", required = false) String pageToken) {
		Map<String, Object> list = youtubeService.getSearchVideos(query, pageToken);
		return ResponseEntity.ok(list);
	}

	@Operation(summary = "특정 유튜브 영상 정보 조회")
	@GetMapping("/{videoId}")
	public ResponseEntity<Map<String, Object>> getVideo(@PathVariable("videoId") String videoId) {
		Map<String, Object> list = youtubeService.getVideo(videoId);
		return ResponseEntity.ok(list);
	}

	// -------- 댓 글 ------------

	@Operation(summary = "영상의 전체 댓글 조회 ")
	@GetMapping("/{videoId}/comment")
	public ResponseEntity<List<Comment>> getVideoComment(@PathVariable("videoId") String videoId) {
		List<Comment> comments = commentService.getVideoCommentList(videoId);
		if (comments == null || comments.size() == 0) {
			return ResponseEntity.noContent().build();
		}
		return ResponseEntity.ok(comments);

	}

	@Operation(summary = "영상 댓글 등록")
	@PostMapping("/{videoId}/comment")
	public ResponseEntity<Void> registVideoComment(@RequestBody Comment comment) {

		if (commentService.registVideoComment(comment)) {
			return ResponseEntity.status(HttpStatus.CREATED).build();
		}
		return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();

	}

	@Operation(summary = "영상 댓글 삭제")
	@DeleteMapping("{videoId}/comment/{videoCommentId}")
	public ResponseEntity<Void> deleteVideoComment(@PathVariable("videoId") String videoId,
			@PathVariable("videoCommentId") int videoCommentId) {

		if (commentService.deleteVideoComment(videoId, videoCommentId)) {

			return ResponseEntity.ok().build();
		}
		return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();

	}

	@Operation(summary = "영상 댓글 수정")
	@PutMapping("/{videoId}/comment/{videoCommentId}")
	public ResponseEntity<Void> updateVideoComment(@RequestBody Comment comment) {

		if (commentService.updateVideoComment(comment)) {
			return ResponseEntity.ok(null);
		}

		return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();

	}

	// ------ 좋아요 -----
	@Operation(summary = "영상 좋아요 수정")
	@PostMapping("/{videoId}/like")
	public ResponseEntity<Void> updateVideoLike(@PathVariable("videoId") String videoId, @RequestBody Like like) {

		if (likeService.updateVideoLike(like))
			return ResponseEntity.ok().build();
		return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
	}

	@Operation(summary = "사용자의 영상 좋아요 여부 및 좋아요 수 조회")
	@GetMapping("/{videoId}/like/{writer}")
	public ResponseEntity<Like> getVideoLike(@PathVariable("videoId") String videoId,
			@PathVariable("writer") String writer) {
		Like like = likeService.getVideoLike(videoId, writer);

		return ResponseEntity.ok(like);

	}

}
