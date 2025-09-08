package com.ssafy.fitcha.model.service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import com.ssafy.fitcha.model.dao.ProofDao;
import com.ssafy.fitcha.model.dto.Proof;
import com.ssafy.fitcha.model.dto.ProofFile;
import com.ssafy.fitcha.model.dto.SearchProof;
import com.ssafy.fitcha.model.dto.User;

@Service
public class ProofServiceImpl implements ProofService {

	// 생성자 의존성 주입
	private ProofDao proofDao;
	private FileService fileService;
	private UserService userService;

	public ProofServiceImpl(ProofDao proofDao, FileService fileService, UserService userService) {
		this.proofDao = proofDao;
		this.fileService = fileService;
		this.userService = userService;
	}

	// 인증글 검색 조회 ( 검색 없으실 전체 조회 )
	@Override
	public List<Proof> getSearchProofs(SearchProof search) {
		List<Proof> proofList = proofDao.selectSearchProofList(search);

		// 1. 인증글 ID만 추출
		List<Integer> proofBoardIds = proofList.stream().map(Proof::getProofBoardId).collect(Collectors.toList());

		if (proofBoardIds.isEmpty()) {
			return proofList; // 게시글 없음
		}

		// 2. 해시태그 목록 가져오기
		List<Map<String, Object>> rawHashtags = proofDao.selectHashTagsByProofBoardIds(proofBoardIds);

		// 3. Map<proofBoardId, List<hashtag>> 형태로 정리
		Map<Integer, List<String>> hashtagMap = new HashMap<>();
		for (Map<String, Object> row : rawHashtags) {
			Integer boardId = (Integer) row.get("proof_board_id");
			String tag = (String) row.get("hashtag");
			hashtagMap.computeIfAbsent(boardId, k -> new ArrayList<>()).add(tag);
		}

		// 4. 인증글에 해시태그 세팅 및 파일정보 세팅
		for (Proof proof : proofList) {
			int boardId = proof.getProofBoardId();

			List<String> tags = hashtagMap.getOrDefault(proof.getProofBoardId(), new ArrayList<>());
			proof.setHashTags(tags);

			// 인증글 이미지 파일 정보
			List<ProofFile> proofFiles = fileService.getProofFileList(boardId);
			proof.setProofFiles(proofFiles); // 이미지 URL 포함

			// 유저 프로필 이미지
			String nickName = proof.getWriter();
			User user = userService.getUserInfo(nickName);
			if(user != null) {
				proof.setUserProfileImgUrl(user.getProfileImgUrl());
			}

		}
		return proofList;
	}
	
	// 챌린지에 해당하는 게시글 조회 
	@Override
	public List<Proof> getSearchProofsByChallenge(int challengeBoardId) {
		List<Proof> proofList = proofDao.selectProofListByChallenge(challengeBoardId);

		// 1. 인증글 ID만 추출
		List<Integer> proofBoardIds = proofList.stream().map(Proof::getProofBoardId).collect(Collectors.toList());

		if (proofBoardIds.isEmpty()) {
			return proofList; // 게시글 없음
		}

		// 2. 해시태그 목록 가져오기
		List<Map<String, Object>> rawHashtags = proofDao.selectHashTagsByProofBoardIds(proofBoardIds);

		// 3. Map<proofBoardId, List<hashtag>> 형태로 정리
		Map<Integer, List<String>> hashtagMap = new HashMap<>();
		for (Map<String, Object> row : rawHashtags) {
			Integer boardId = (Integer) row.get("proof_board_id");
			String tag = (String) row.get("hashtag");
			hashtagMap.computeIfAbsent(boardId, k -> new ArrayList<>()).add(tag);
		}

		// 4. 인증글에 해시태그 세팅 및 파일정보 세팅
		for (Proof proof : proofList) {
			int boardId = proof.getProofBoardId();

			List<String> tags = hashtagMap.getOrDefault(proof.getProofBoardId(), new ArrayList<>());
			proof.setHashTags(tags);

			// 인증글 이미지 파일 정보
			List<ProofFile> proofFiles = fileService.getProofFileList(boardId);
			proof.setProofFiles(proofFiles); // 이미지 URL 포함

			// 유저 프로필 이미지
			String nickName = proof.getWriter();
			User user = userService.getUserInfo(nickName);
			proof.setUserProfileImgUrl(user.getProfileImgUrl());
			
		}

		return proofList;
	}

	// 인증글 상세 조회
	@Override
	public Proof getProofDetails(int proofBoardId) {
		Proof proof = proofDao.selectProofBoard(proofBoardId);

		// 인증글에 파일 세팅
		List<ProofFile> proofFiles = fileService.getProofFileList(proofBoardId);
		proof.setProofFiles(proofFiles);

		// 인증글에 해쉬태그 세팅
		proof.setHashTags(proofDao.selectHashTagByProofBoardId(proofBoardId));

		return proof;
	}

	// 인증글 등록
	@Override
	public boolean registProof(Proof proof, List<MultipartFile> files) throws Exception {
		// 인증글 저장
		boolean isRegisted = (1 == proofDao.insertProofBoard(proof));
		int proofBoardId = proof.getProofBoardId();

		fileService.insertProofFile(files, proof.getProofBoardId(), proof.getWriter());

		// 해쉬태그 저장
		List<String> hashTags = proof.getHashTags();
		if (hashTags != null && !hashTags.isEmpty()) {
		    Map<String, Object> params = new HashMap<>();
		    params.put("proofBoardId", proofBoardId);
		    params.put("hashTags", hashTags);
		    proofDao.insertProofBoardHashtags(params);
		}

		return isRegisted;
	}

	// 인증글 수정
	@Override
	public boolean updateProof(Proof proof, List<MultipartFile> files) throws Exception {
		boolean isUpdated = (1 == proofDao.updateProofBoard(proof));

		// 해쉬태그 수정을 위해 기존에 있는 해쉬 태그 삭제 후 새로운 해쉬태그들 등록
		proofDao.deleteProofBoardHashtags(proof.getProofBoardId());

		List<String> hashTags = proof.getHashTags();
		if (hashTags != null && !hashTags.isEmpty()) {
		    Map<String, Object> params = new HashMap<>();
		    params.put("proofBoardId", proof.getProofBoardId());
		    params.put("hashTags", hashTags);
		    proofDao.insertProofBoardHashtags(params);
		}
		
		// 인증글 파일 교체
		if (files != null && files.size() > 0) {
			fileService.updateProofFile(files, proof.getProofBoardId(), proof.getWriter());
		}
		return isUpdated;
	}

	// 인증 글 삭제
	@Override
	public boolean deleteProofBoard(int challengeFileId) {
		return 1 == proofDao.deleteProofBoard(challengeFileId);
	}

	// 챌린지 글 삭제시 내 인증글 삭제
	@Override
	public boolean deleteMyProofBoard(Proof proof) {
		return 1 == proofDao.deleteMyProofBoard(proof);
	}

	// 인증글 조회수 증가
	@Override
	public void increaseViewCount(int proofBoardId) {
		proofDao.increaseViewCount(proofBoardId);
	}
	
	// 인증글 이미지 조회 
	@Override
	public List<String> getProofImages() {
		
		return proofDao.selectProofImages();
	}

	

}
