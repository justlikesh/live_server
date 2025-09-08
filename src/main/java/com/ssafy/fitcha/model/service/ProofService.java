package com.ssafy.fitcha.model.service;

import java.util.List;

import org.springframework.web.multipart.MultipartFile;

import com.ssafy.fitcha.model.dto.Proof;
import com.ssafy.fitcha.model.dto.SearchProof;


public interface ProofService {
	
	// 인증글 검색 조회 (검색 없으면 전체 조회)
	List<Proof> getSearchProofs(SearchProof search);
	
	// 인증글 상세 조회 
	Proof getProofDetails(int proofBoardId);

	// 인증글 등록
	boolean registProof(Proof proof, List<MultipartFile> file) throws Exception;
	
	// 인증글 수정
	boolean updateProof(Proof proof, List<MultipartFile> files) throws Exception;
	
	// 인증글 삭제
	boolean deleteProofBoard(int challengeFileId);

	//챌린지글 삭제시 내 인증글 삭제
	boolean deleteMyProofBoard(Proof proof);
	
	// 인증글 조회수 증가 
	void increaseViewCount(int proofBoardId);
	
	// 챌린지에 해당하는 게시글들 조회 
	List<Proof> getSearchProofsByChallenge(int challengeBoardId);
	
	// 인증글 이미지 url 전체 조회 
	List<String> getProofImages();
	

}
