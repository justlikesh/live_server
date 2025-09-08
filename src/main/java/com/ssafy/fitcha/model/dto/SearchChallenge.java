package com.ssafy.fitcha.model.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description="챌린지 검색 DTO")
public class SearchChallenge {
	//직접 입력하여 검색 
	private String key; //title, content, both(title,content),writer
	private String word;
	
	//필터 선택
	private String exerciseType;
	private String bodyPart;
	private String level;
	private int duration;
	private int totalParticipantCount;
	public String getKey() {
		return key;
	}
	public void setKey(String key) {
		this.key = key;
	}
	public String getWord() {
		return word;
	}
	public void setWord(String word) {
		this.word = word;
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

	public int getTotalParticipantCount() {
		return totalParticipantCount;
	}
	public void setTotalParticipantCount(int totalParticipantCount) {
		this.totalParticipantCount = totalParticipantCount;
	}

	
	
	
	
}
