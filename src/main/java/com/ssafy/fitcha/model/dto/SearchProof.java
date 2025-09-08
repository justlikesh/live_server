package com.ssafy.fitcha.model.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description="인증 게시글 검색 DTO")
public class SearchProof {

	private String key; // 제목 검색, 내용 검색, 작성자 검색, 제목+내용 검색
	private String word; // 검색 내용
	private String orderBy; // 정렬 기준
	private String orderByDir; // 정렬 방향 (오름차순, 내림차순)

	// 생성자
	public SearchProof() {
	}

	// getter/setter
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

	public String getOrderBy() {
		return orderBy;
	}

	public void setOrderBy(String orderBy) {
		this.orderBy = orderBy;
	}

	public String getOrderByDir() {
		return orderByDir;
	}

	public void setOrderByDir(String orderByDir) {
		this.orderByDir = orderByDir;
	}

	@Override
	public String toString() {
		return "SearchProof [key=" + key + ", word=" + word + ", orderBy=" + orderBy + ", orderByDir=" + orderByDir
				+ "]";
	}

}
