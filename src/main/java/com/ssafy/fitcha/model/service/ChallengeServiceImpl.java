package com.ssafy.fitcha.model.service;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Random;

import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import com.ssafy.fitcha.model.dao.ChallengeDao;
import com.ssafy.fitcha.model.dto.Challenge;
import com.ssafy.fitcha.model.dto.ChallengeFile;
import com.ssafy.fitcha.model.dto.Comment;
import com.ssafy.fitcha.model.dto.Participate;
import com.ssafy.fitcha.model.dto.Proof;
import com.ssafy.fitcha.model.dto.SearchChallenge;
import com.ssafy.fitcha.model.dto.User;

@Service
public class ChallengeServiceImpl implements ChallengeService {
	private ChallengeDao challengeDao;
	private FileService fileService;
	private ProofService proofService;
	private CommentService commentService;
	private LikeService likeService;
	private UserService userService;

	public ChallengeServiceImpl(ChallengeDao challengeDao, FileService fileService, ProofService proofService,
			CommentService commentService, LikeService likeService, UserService userService) {
		this.challengeDao = challengeDao;
		this.fileService = fileService;
		this.proofService = proofService;
		this.commentService = commentService;
		this.likeService = likeService;
		this.userService = userService;
	}

	@Override
	// 검색 목록 조회 (검색어 없을 시 전체 조회)
	public List<Challenge> getSearchChallenges(SearchChallenge search) {
		List<Challenge> challengeBoardList = challengeDao.selectSearchChallengeBoardList(search);

		for (Challenge challenge : challengeBoardList) {
			int challengeBoardId = challenge.getChallengeBoardId();
			challenge.setChallengeFiles(fileService.getChallengeFileList(challengeBoardId));
			challenge.setComments(commentService.getChallengeCommentList(challenge.getChallengeBoardId()));
			challenge.setParticipantCount(challengeDao.selectChallengeParticipantCount(challengeBoardId));

			// 종료되었는지 확인후 저장
			checkAndUpdateFinish(challenge);

			// 유저 프로필 이미지
			String nickName = challenge.getWriter();
			User user = userService.getUserInfo(nickName);
			challenge.setUserProfileImgUrl(user.getProfileImgUrl());

		}
		return challengeBoardList;
	}

	// 상세 조회
	@Override
	public Challenge getChallengeDetail(int challengeBoardId, String nickName, String isViewCounted) {
		// 조회일때만 조회수 증가.
		if (Boolean.parseBoolean(isViewCounted))
			challengeDao.updateChallengeViewCount(challengeBoardId);

		Challenge challenge = challengeDao.selectChallengeBoard(challengeBoardId);
		challenge.setParticipantCount(challengeDao.selectChallengeParticipantCount(challengeBoardId));

		// 현재 유저가 참여중인 챌린지인지
		Participate participate = new Participate(challengeBoardId, nickName);
		challenge.setParticipated(challengeDao.selectChallengeParticipated(participate) == 1);

		int participantCount = challengeDao.selectChallengeParticipantCount(challengeBoardId);
		challenge.setParticipantCount(participantCount);

		// 파일 목록 조회
		List<ChallengeFile> files = fileService.getChallengeFileList(challengeBoardId);
		challenge.setChallengeFiles(files);
		// 댓글 목록 조회
		List<Comment> comments = commentService.getChallengeCommentList(challengeBoardId);
		challenge.setComments(comments);

		// 로그인 유저의 챌린지글 좋아요 여부
		boolean isLiked = likeService.getChallengeLike(challengeBoardId, nickName).getLike() == 1;
		challenge.setLiked(isLiked);

		// 챌린지 종료되었는지 확인 후 저장
		checkAndUpdateFinish(challenge);

		// 유저 프로필 이미지
		String writer = challenge.getWriter();
		User user = userService.getUserInfo(writer);
		challenge.setUserProfileImgUrl(user.getProfileImgUrl());
		System.out.println(user);

		return challenge;
	}

	// 수정 (챌린지 보드 : 수정, 챌린지 파일 : 등록 및 삭제)
	@Override
	public boolean updateChallenge(Challenge challenge, List<MultipartFile> files, List<Integer> deleteChallengeFileIds)
			throws Exception {
		boolean isOk = challengeDao.updateChallengeBoard(challenge) == 1;
		// 챌린지 파일 삭제
		if (deleteChallengeFileIds != null && deleteChallengeFileIds.size() > 0) {
			fileService.deleteChallengeFile(deleteChallengeFileIds);

		}
		// 챌린지 파일 등록 (새로 추가된것 등록)
		if (files != null && files.size() > 0) {
			fileService.insertChallengeFile(files, challenge.getChallengeBoardId(), challenge.getWriter());

		}
		return isOk;

	}

	// 삭제
	@Override
	public boolean deleteChallenge(int challengeBoardId, String writer) {

		// 챌린지 삭제시 내가쓴 인증글과 파일 삭제
		Proof deleteProof = new Proof();
		deleteProof.setChallengeBoardId(challengeBoardId);
		deleteProof.setWriter(writer);
		proofService.deleteMyProofBoard(deleteProof);

		// 내가쓴 챌린지글과 파일 삭제
		return 1 == challengeDao.deleteChallengeBoard(challengeBoardId);

	}

	// 등록
	@Override
	public boolean registChallenge(Challenge challenge, List<MultipartFile> files) throws Exception {

		// GPT를 호출해서 소제목 받아오기
//      String subhead = openaiService.getSubheadFromGPT(challenge.getTitle(), challenge.getContent());
//      if(subhead!=null)challenge.setSubhead(subhead);
//      else {
		List<String> fallbackSubheads = Arrays.asList("오늘도 움직이는 나, 내일 더 멋진 나를 만든다", "가벼운 운동이 쌓여 무거운 피로를 밀어낸다",
				"내 몸을 아끼는 첫걸음, 지금 바로 시작해요", "반복이 쌓이면 변화가 된다, 운동 루틴 만들기", "땀은 배신하지 않는다, 하루 한 번 나와의 약속",
				"천천히, 하지만 확실하게 건강을 채워가요", "지치지 않게, 매일 가볍게, 꾸준히 운동하기", "오늘의 땀 한 방울이 내일의 활력 한 스푼", "어제보다 나은 나를 위한 작은 실천",
				"몸도 마음도 가볍게, 내일을 위한 움직임");

		// 랜덤으로 하나 선택
		Random random = new Random();
		String randomSubhead = fallbackSubheads.get(random.nextInt(fallbackSubheads.size()));
		challenge.setSubhead(randomSubhead);
//      }

		boolean isOk = challengeDao.insertChallengeBoard(challenge) == 1;
		fileService.insertChallengeFile(files, challenge.getChallengeBoardId(), challenge.getWriter());
		challengeDao.insertParticipantChallenge(challenge);

		return isOk;
	}

	// 최근등록한| 참여자수 많은| 좋아요많은 | 조회수 많은 챌린지글 조회
	@Override
	public List<Challenge> getTop10Challenges(String orderBy) {
		List<Challenge> challengeBoardList = challengeDao.selectTop10Challenges(orderBy);
		for (Challenge challenge : challengeBoardList) {
			int challengeBoardId = challenge.getChallengeBoardId();
			challenge.setChallengeFiles(fileService.getChallengeFileList(challengeBoardId));
		}
		return challengeBoardList;
	}

	// 챌린지 참여 등록
	@Override
	public boolean registChallengeParticipate(Challenge challenge) {
		challengeDao.increaseParticipantCount(challenge.getChallengeBoardId());
		return challengeDao.insertParticipantChallenge(challenge) == 1;
	}

	// 챌린지 참여 취소
	@Override
	public boolean deleteChallengeParticipate(int challengeBoardId, String writer) {
		challengeDao.decreaseParticipantCount(challengeBoardId);
		Participate participate = new Participate(challengeBoardId, writer);

		return challengeDao.deleteChallengeParticipate(participate) == 1;
	}

	// 유저가 참여한 챌린지 조회
	@Override
	public List<Challenge> getChallengeByNickName(String userNickName) {

		List<Challenge> challengeBoardList = challengeDao.selectChallengeByNickName(userNickName);

		for (Challenge challenge : challengeBoardList) {
			int challengeBoardId = challenge.getChallengeBoardId();
			challenge.setChallengeFiles(fileService.getChallengeFileList(challengeBoardId));

			// 종료되었는지 확인후 저장
			checkAndUpdateFinish(challenge);

			// 유저 프로필 이미지
			String nickName = challenge.getWriter();
			User user = userService.getUserInfo(nickName);
			challenge.setUserProfileImgUrl(user.getProfileImgUrl());

		}
		return challengeBoardList;

	}

	/**
	 * regDate + duration 기간이 지났으면 finish 를 true 로 바꿔서 DTO에 반영하고 DB에도 동기화한다.
	 */
	private static final DateTimeFormatter DATE_FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd");

	private void checkAndUpdateFinish(Challenge c) {
		if (c.isFinish()) {
			return;
		}

		// regDate의 "yyyy-MM-dd HH:mm:ss" -> yyyy-MM-dd 로 파싱
		LocalDate start = LocalDate.parse(c.getRegDate().substring(0, 10), DATE_FMT);
		LocalDate end = start.plusDays(c.getDuration());

		// 종료일 지났으면 true로 바꿈
		if (LocalDate.now().isAfter(end)) {
			// 3-1) DTO에 반영
			c.setFinish(true);
			// 3-2) DB에도 반영
			challengeDao.updateChallengeFinish(c.getChallengeBoardId());
		}
	}

	@Override
	public List<Map<String, Object>> getTop5Challengers() {
		return challengeDao.selectTop5Challengers();
	}

}
