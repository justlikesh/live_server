package com.ssafy.fitcha.model.dto;

import java.util.List;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "챌린지 게시글 DTO")
public class Challenge {

	private int challengeBoardId;
	private String UserId;
	private String title;
	private String content;
	private String writer;
	private String exerciseType;
	private String bodyPart;
	private String level;
	private int duration; // 실제 기간.
	private int participantCount; // 실제 참여중인 인원
	private int totalParticipantCount; // 설정한 참여 인원
	private int viewCount;
	private int likeCount;
	private String regDate; // 챌린지 등록일
	private List<ChallengeFile> challengeFiles;
	private List<Comment> comments;
	private boolean isLiked; // 로그인 유저의 좋아요여부.
	private boolean isParticipated; // 로그인 유저의 참여 여부.
	private String userProfileImgUrl; // 유저 프로필 이미지 


	private boolean finish; // 챌린지 종료

	private String subhead;

	
	
	public String getUserProfileImgUrl() {
		return userProfileImgUrl;
	}

	public void setUserProfileImgUrl(String userProfileImgUrl) {
		this.userProfileImgUrl = userProfileImgUrl;
	}

	public String getSubhead() {
		return subhead;
	}

	public void setSubhead(String subhead) {
		this.subhead = subhead;
	}

	public boolean isFinish() {
		return finish;
	}

	public void setFinish(boolean finish) {
		this.finish = finish;
	}

	public int getChallengeBoardId() {
		return challengeBoardId;
	}

	public void setChallengeBoardId(int challengeBoardId) {
		this.challengeBoardId = challengeBoardId;
	}

	public String getUserId() {
		return UserId;
	}

	public void setUserId(String userId) {
		UserId = userId;
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

	public int getDuration() {
		return duration;
	}

	public void setDuration(int duration) {
		this.duration = duration;
	}

	public int getParticipantCount() {
		return participantCount;
	}

	public void setParticipantCount(int participantCount) {
		this.participantCount = participantCount;
	}

	public int getTotalParticipantCount() {
		return totalParticipantCount;
	}

	public void setTotalParticipantCount(int totalParticipantCount) {
		this.totalParticipantCount = totalParticipantCount;
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

	public String getRegDate() {
		return regDate;
	}

	public void setRegDate(String regDate) {
		this.regDate = regDate;
	}

	public List<ChallengeFile> getChallengeFiles() {
		return challengeFiles;
	}

	public void setChallengeFiles(List<ChallengeFile> challengeFiles) {
		this.challengeFiles = challengeFiles;
	}

	public List<Comment> getComments() {
		return comments;
	}

	public void setComments(List<Comment> comments) {
		this.comments = comments;
	}

	public boolean isLiked() {
		return isLiked;
	}

	public void setLiked(boolean isLiked) {
		this.isLiked = isLiked;
	}

	public boolean isParticipated() {
		return isParticipated;
	}

	public void setParticipated(boolean isParticipated) {
		this.isParticipated = isParticipated;
	}

}
