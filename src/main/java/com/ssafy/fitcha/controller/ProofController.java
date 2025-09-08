package com.ssafy.fitcha.controller;

import java.net.URI;
import java.util.Collections;
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

import com.ssafy.fitcha.model.dto.CommentProof;
import com.ssafy.fitcha.model.dto.Proof;
import com.ssafy.fitcha.model.dto.SearchProof;
import com.ssafy.fitcha.model.service.CommentService;
import com.ssafy.fitcha.model.service.LikeService;
import com.ssafy.fitcha.model.service.ProofService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@RestController
@RequestMapping("/proof")
@Tag(name = "Proof RESTful API", description = "챌린지 게시글의 인증 게시판 CRUD")
public class ProofController {

	// 생성자 의존성 주입
	private ProofService proofService;
	private CommentService commentService;
	private LikeService likeService;

	public ProofController(ProofService proofService, CommentService commentService, LikeService likeService) {
		this.proofService = proofService;
		this.commentService = commentService;
		this.likeService = likeService;
	}

	@Operation(summary = "인증글 게시글 검색 및 전체 목록 조회")
	@GetMapping
	public ResponseEntity<List<Proof>> getSearchProofs(@ModelAttribute SearchProof search) {
		List<Proof> proofList = null; // 인증글 전체 리스트
		try {
			proofList = proofService.getSearchProofs(search);
			if (proofList == null || proofList.isEmpty()) {
				return ResponseEntity.noContent().build();
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return ResponseEntity.ok(proofList);

	}
	
	@Operation(summary = "인증글 이미지들 불러오기 (홈 뷰에서 사용)")
	@GetMapping("/images")
	public ResponseEntity<List<String>> getProofImages() {
		List<String> proofImageList = null; // 인증글 사진 전체 리스트
		try {
			proofImageList = proofService.getProofImages();
			if (proofImageList == null || proofImageList.isEmpty()) {
				return ResponseEntity.noContent().build();
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return ResponseEntity.ok(proofImageList);

	}
	
	@Operation(summary = "챌린지에 해당하는 인증글 게시글 조회")
	@GetMapping("/byChallenge/{challengeBoardId}")
	public ResponseEntity<List<Proof>> getSearchProofsByChallenge(@PathVariable("challengeBoardId") int challengeBoardId) {
		List<Proof> proofList = null; // 인증글 전체 리스트
		try {
			proofList = proofService.getSearchProofsByChallenge(challengeBoardId);
			if (proofList == null || proofList.isEmpty()) {
				return ResponseEntity.noContent().build();
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return ResponseEntity.ok(proofList);

	}

	@Operation(summary = "인증글 게시글 상세 조회")
	@GetMapping("/{proofBoardId}")
	public ResponseEntity<Proof> getDetailProof(@PathVariable("proofBoardId") int proofBoardId,
			HttpServletRequest request, HttpServletResponse response) {

		// 쿠키 이름 정의
		String cookieName = "viewed_proof_" + proofBoardId;
		boolean isViewed = false;

		// 기존 쿠키들 확인
		Cookie[] cookies = request.getCookies();
		if (cookies != null) {
			for (Cookie cookie : cookies) {
				if (cookie.getName().equals(cookieName)) {
					isViewed = true;
					break;
				}
			}
		}

		// 조회수 증가 로직 - 쿠키에 없을 때만
		if (!isViewed) {
			proofService.increaseViewCount(proofBoardId);

			// 새 쿠키 생성 (예: 1시간 동안 유지)
			Cookie viewCookie = new Cookie(cookieName, "true");
			viewCookie.setMaxAge(60 * 60); // 1시간
			viewCookie.setPath("/"); // 전체 경로에서 유효
			response.addCookie(viewCookie);
		}

		// 게시글 상세정보 반환
		Proof proof = proofService.getProofDetails(proofBoardId);
		if (proof == null) {
			return ResponseEntity.noContent().build();
		}

		return ResponseEntity.ok(proof);
	}

	@Operation(summary = "인증글 게시글 등록")
	@PostMapping
	public ResponseEntity<Integer> registProof(
			@RequestParam(value = "files", required = false) List<MultipartFile> files, @ModelAttribute Proof proof)
			throws Exception {

		if (proofService.registProof(proof, files))
			return ResponseEntity.ok(proof.getProofBoardId());

		return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
	}

	@Operation(summary = "인증글 게시글 수정 ")
	@PutMapping("/{proofBoardId}")
	public ResponseEntity<Void> updateProof(@PathVariable("proofBoardId") int proofBoardId, @ModelAttribute Proof proof,
			@RequestParam(value = "files", required = false) List<MultipartFile> files// 새로운 파일

	) throws Exception {
		proof.setProofBoardId(proofBoardId);
		boolean isUpdated = proofService.updateProof(proof, files);

		if (isUpdated) {
			return ResponseEntity.ok().build();
		}

		return ResponseEntity.badRequest().build();
	}

	@Operation(summary = "인증글 게시글 삭제")
	@DeleteMapping("/{proofBoardId}")
	public ResponseEntity<Void> deleteProof(@PathVariable("proofBoardId") int proofBoardId) {
		if (proofService.deleteProofBoard(proofBoardId)) {
			return ResponseEntity.ok().build();
		}
		return ResponseEntity.badRequest().build();

	}

	// ---댓글-------------------------------------------------------------------------------

	@Operation(summary = "인증글 게시글의 전체 댓글 조회 ")
	@GetMapping("/{proofBoardId}/comment")
	public ResponseEntity<List<CommentProof>> getProofCommentAll(@PathVariable("proofBoardId") int proofBoardId) {

		List<CommentProof> comments = commentService.getProofCommentList(proofBoardId);
		if (comments == null || comments.size() == 0) {
			return ResponseEntity.noContent().build();
		}
		return ResponseEntity.ok(comments);

	}

	@Operation(summary = "인증글 게시글의 댓글 등록")
	@PostMapping("/{proofBoardId}/comment")
	public ResponseEntity<Void> registProofComment(@PathVariable("proofBoardId") int proofBoardId,
			@RequestBody CommentProof comment) {

		if (commentService.registProofComment(proofBoardId, comment)) {
			return ResponseEntity.ok().build();
		}
		return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();

	}

	@Operation(summary = "인증글 게시글의 댓글 삭제")
	@DeleteMapping("/{proofBoardId}/comment/{proofCommentId}")
	public ResponseEntity<Void> deleteProofComment(@PathVariable("proofBoardId") int proofBoardId,
			@PathVariable("proofCommentId") int proofCommentId) {
		if (commentService.deleteProofComment(proofBoardId, proofCommentId)) {
			URI redirectUri = URI.create("/proof/" + proofBoardId);
			return ResponseEntity.status(HttpStatus.SEE_OTHER).location(redirectUri).build();
		}
		return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
	}

	@Operation(summary = "인증글 게시글의 댓글 수정")
	@PutMapping("/{proofBoardId}/comment/{proofCommentId}")
	public ResponseEntity<Void> updateProofComment(@PathVariable("proofBoardId") int proofBoardId,
			@PathVariable("proofCommentId") int proofCommentId, @RequestBody CommentProof comment) {

		if (commentService.updateProofComment(proofBoardId, proofCommentId, comment)) {
			URI redirectUri = URI.create("/proof/" + proofBoardId);
			return ResponseEntity.status(HttpStatus.SEE_OTHER).location(redirectUri).build();
		}

		return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();

	}

	// ----- 좋아요-----
	@Operation(summary = "인증 게시글 좋아요 추가")
	// 좋아요 추가
	@PostMapping("/{proofBoardId}/like")
	public ResponseEntity<Void> addLike(@PathVariable int proofBoardId, @RequestBody Map<String, String> body) {
		String nickName = body.get("nickName");
		boolean success = likeService.addLike(proofBoardId, nickName);
		return success ? ResponseEntity.ok().build() : ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
	}

	@Operation(summary = "인증 게시글 좋아요 취소")
	// 좋아요 취소
	@DeleteMapping("/{proofBoardId}/like")
	public ResponseEntity<Void> removeLike(@PathVariable int proofBoardId, @RequestBody Map<String, String> body) {
		String nickName = body.get("nickName");
		boolean success = likeService.removeLike(proofBoardId, nickName);
		return success ? ResponseEntity.ok().build() : ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
	}

	@Operation(summary = "인증 게시글 좋아요 눌렀는지 체크 ")
	@GetMapping("/{proofBoardId}/like/check")
	public ResponseEntity<Map<String, Boolean>> checkLiked(@PathVariable int proofBoardId,
			@RequestParam String writer) {
		boolean liked = likeService.checkLikeByWriter(proofBoardId, writer);
		return ResponseEntity.ok(Collections.singletonMap("liked", liked));
	}

}
