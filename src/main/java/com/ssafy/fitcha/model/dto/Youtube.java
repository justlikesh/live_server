package com.ssafy.fitcha.model.dto;

import io.swagger.v3.oas.annotations.media.Schema;

//import lombok.AllArgsConstructor;
//import lombok.Getter;
//import lombok.NoArgsConstructor;
//import lombok.Setter;
//
//@Getter
//@Setter
//@NoArgsConstructor
//@AllArgsConstructor
@Schema(description="유튜브 정보 DTO")
public class Youtube {
	private String videoId; // 유튜브 영상의 고유 아이디.
	private String title; // 영상제목
	private String videoUrl; // 영상 URL (https://www.youtube.com/watch?v=xxx)
	private String iframe; // 영상 embed iframe 태그
	private String description; // 영상설명 텍스트
	private String thumbnailUrl; // 썸네일주소(미리보기이미지 주소)
	private String channelTitle; // 영성을 업로드한 유튜브 채널의 이름
	private String publishedAt; // 영상이 업로드된 날짜

	public Youtube(String videoId, String title, String videoUrl, String iframe, String description,
			String thumbnailUrl, String channelTitle, String publishedAt) {
		this.videoId = videoId;
		this.title = title;
		this.videoUrl = videoUrl;
		this.iframe = iframe;
		this.description = description;
		this.thumbnailUrl = thumbnailUrl;
		this.channelTitle = channelTitle;
		this.publishedAt = publishedAt;
	}

	public String getVideoId() {
		return videoId;
	}

	public void setVideoId(String videoId) {
		this.videoId = videoId;
	}

	public String getTitle() {
		return title;
	}

	public void setTitle(String title) {
		this.title = title;
	}

	public String getVideoUrl() {
		return videoUrl;
	}

	public void setVideoUrl(String videoUrl) {
		this.videoUrl = videoUrl;
	}

	public String getIframe() {
		return iframe;
	}

	public void setIframe(String iframe) {
		this.iframe = iframe;
	}

	public String getDescription() {
		return description;
	}

	public void setDescription(String description) {
		this.description = description;
	}

	public String getThumbnailUrl() {
		return thumbnailUrl;
	}

	public void setThumbnailUrl(String thumbnailUrl) {
		this.thumbnailUrl = thumbnailUrl;
	}

	public String getChannelTitle() {
		return channelTitle;
	}

	public void setChannelTitle(String channelTitle) {
		this.channelTitle = channelTitle;
	}

	public String getPublishedAt() {
		return publishedAt;
	}

	public void setPublishedAt(String publishedAt) {
		this.publishedAt = publishedAt;
	}

}