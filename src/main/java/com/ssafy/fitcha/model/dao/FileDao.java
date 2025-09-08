package com.ssafy.fitcha.model.dao;

import java.util.List;

import com.ssafy.fitcha.model.dto.ChallengeFile;
import com.ssafy.fitcha.model.dto.ProofFile;

public interface FileDao {

	//챌린지파일 목록 조회
	public List<ChallengeFile> selectChallengeFileList(int challengeBoardId);
	
	// 챌린파일 수정
	public void updateChallengeFiles(List<ChallengeFile> files);
	
	// 챌린지파일 삭제 : 파일 고유번호로 삭제
	public void deleteChallengeFile(int challengeFileId);
	
	// 챌린지파일 등록 
	public void insertChallengeFile(ChallengeFile challengeFile);
	
	// ----------------- 인증글 파일 -----------------------------------------------------
	
	// 인증글 파일 목록 조회 
	public List<ProofFile> selectProofFileList(int proofBoardId);
	
	// 인증글 파일 수정
	public void updateProofFiles(List<ProofFile> files);
	
	// 인증글 파일 삭제
	public void deleteProofFile(int proofFileId);

	// 인증글 파일 등록
	public void insertProofFile(ProofFile proofFile);
	
	// 인증글 파일 수정
	public void updateProofFile(ProofFile proofFile);
}
