package com.ssafy.fitcha.model.dao;

import java.util.List;
import java.util.Map;

import com.ssafy.fitcha.model.dto.Proof;
import com.ssafy.fitcha.model.dto.SearchProof;

public interface ProofDao {

	// 인증글 검색 조회 (검색 조건 없으실 전체 조회)
	List<Proof> selectSearchProofList(SearchProof search);

	// 인증글 상세 조회
	Proof selectProofBoard(int proofBoardId);

	// 인증글 등록
	int insertProofBoard(Proof proof);

	// 인증글 수정
	int updateProofBoard(Proof proof);

	// 인증글 삭제
	int deleteProofBoard(int challengeFileId);

	// 챌린지글 삭제시 내 인증글 삭제
	int deleteMyProofBoard(Proof proof);

	// 인증글에 있는 해쉬 태그 별도 테이블에 저장
	int insertProofBoardHashtags(Map<String, Object> map);
	
	// 인증글에 해당하는 해쉬태그 가져오기
	List<Map<String, Object>> selectHashTagsByProofBoardIds(List<Integer> proofBoardIds);
	
	// 인증글 상세 보기에서 해쉬태그 가져오기 
	List<String> selectHashTagByProofBoardId(int proofBoardId);
	
	// 인증글 수정을 위해 해쉬태그 삭제 
	void deleteProofBoardHashtags(int proofBoardId);
	
	// 인증글 조회수 증가 
	void increaseViewCount(int proofBoardId);
	
	// 챌린지에 해당하는 게시글 조회 
	List<Proof> selectProofListByChallenge(int challengeBoardId);
	
	// 인증글 이미지 전체 조회 
	List<String> selectProofImages();

}
