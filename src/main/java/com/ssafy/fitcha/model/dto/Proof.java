package com.ssafy.fitcha.model.dto;

import java.util.List;

import org.springframework.web.multipart.MultipartFile;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "인증 게시글 DTO")
public class Proof {

	// 생성자
	public Proof() {
	}

	private int challengeBoardId; // 연동된 챌린지 게시글 아이디
	private int proofBoardId; // 인증글 식별 id
	private String userId; // 작성자 식별 id
	private String title; // 제목
	private String content; // 내용
	private String writer; // 작성자
	private int viewCount; // 조회수
	private int likeCount; // 좋아요수
	private String regDate; // 작성일
	private List<ProofFile> proofFiles; // 인증글 파일 리스트
	// 챌린지 글에서 설정한 운동 타입, 부위, 레벨
	private String exerciseType;
	private String bodyPart;
	private String level;
	private String userProfileImgUrl; // 유저 프로필 이미지 
	private List<String> hashTags; // 해쉬태그

	
	
	public String getUserProfileImgUrl() {
		return userProfileImgUrl;
	}

	public void setUserProfileImgUrl(String userProfileImgUrl) {
		this.userProfileImgUrl = userProfileImgUrl;
	}

	public List<ProofFile> getProofFiles() {
		return proofFiles;
	}

	public void setProofFiles(List<ProofFile> proofFiles) {
		this.proofFiles = proofFiles;
	}

	public List<String> getHashTags() {
		return hashTags;
	}

	public void setHashTags(List<String> hashTags) {
		this.hashTags = hashTags;
	}

	public String getExerciseType() {
		return exerciseType;
	}

	public void setExerciseType(String exerciseType) {
		this.exerciseType = exerciseType;
	}

	public String getBodyPart() {
		return bodyPart;
	}

	public void setBodyPart(String bodyPart) {
		this.bodyPart = bodyPart;
	}

	public String getLevel() {
		return level;
	}

	public void setLevel(String level) {
		this.level = level;
	}

	public int getViewCount() {
		return viewCount;
	}

	public void setViewCount(int viewCount) {
		this.viewCount = viewCount;
	}

	public int getLikeCount() {
		return likeCount;
	}

	public void setLikeCount(int likeCount) {
		this.likeCount = likeCount;
	}

	// getter / setter
	public int getChallengeBoardId() {
		return challengeBoardId;
	}

	public void setChallengeBoardId(int challengeBoardId) {
		this.challengeBoardId = challengeBoardId;
	}

	public int getProofBoardId() {
		return proofBoardId;
	}

	public void setProofBoardId(int proofBoardId) {
		this.proofBoardId = proofBoardId;
	}

	public String getUserId() {
		return userId;
	}

	public void setUserId(String userId) {
		this.userId = userId;
	}

	public String getTitle() {
		return title;
	}

	public void setTitle(String title) {
		this.title = title;
	}

	public String getContent() {
		return content;
	}

	public void setContent(String content) {
		this.content = content;
	}

	public String getWriter() {
		return writer;
	}

	public void setWriter(String writer) {
		this.writer = writer;
	}

	public String getRegDate() {
		return regDate;
	}

	public void setRegDate(String regDate) {
		this.regDate = regDate;
	}

	@Override
	public String toString() {
		return "Proof [challengeBoardId=" + challengeBoardId + ", proofBoardId=" + proofBoardId + ", userId=" + userId
				+ ", title=" + title + ", content=" + content + ", writer=" + writer + ", viewCount=" + viewCount
				+ ", likeCount=" + likeCount + ", regDate=" + regDate + ", proofFiles=" + proofFiles + ", exerciseType="
				+ exerciseType + ", bodyPart=" + bodyPart + ", level=" + level + ", hashTags=" + hashTags + "]";
	}
	
	
	
}
