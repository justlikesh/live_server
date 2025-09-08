package com.ssafy.fitcha.model.dto;

public class Participate {
	private int challengeBoardId;
	private String participant;

	public int getChallengeBoardId() {
		return challengeBoardId;
	}

	public void setChallengeBoardId(int challengeBoardId) {
		this.challengeBoardId = challengeBoardId;
	}

	public String getParticipant() {
		return participant;
	}

	public void setParticipant(String participant) {
		this.participant = participant;
	}

	public Participate(int challengeBoardId, String participant) {
		this.challengeBoardId = challengeBoardId;
		this.participant = participant;
	}

	public Participate() {

	}

}
