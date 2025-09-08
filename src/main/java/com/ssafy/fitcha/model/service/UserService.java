package com.ssafy.fitcha.model.service;

import java.util.List;
import java.util.Map;

import com.ssafy.fitcha.model.dto.User;

public interface UserService {

	// 유저 회원가입
	boolean registUser(User user);

	// 유저 탈퇴
	boolean deleteUser(int userBoardId);

	// 유저 로그인
	User login(User user);

	
	// 유저 팔로우 
	boolean follow(String followerNickName, String followingNickName);

	// 유저 언팔로우 
	boolean unfollow(String followerNickName, String followingNickName);
	
	// 유저 팔로워 팔로잉 수 조회 
	Map<String, Integer> getFollowAllCount(String nickName);
	
	// 유저 팔로워 전체 조회 
	List<String> getFollowerAllList(String userNickName);
	
	// 유저 팔로잉 전체 조회 
	List<String> getFollowingAllList(String userNickName);
	
	// 유저 정보 조회 
	User getUserInfo(String userNickName);
	
	// 유저 정보 수정
	boolean updateUserInfo(User user);
	
	// 상대발 팔로우 하는지 체크 
	boolean isFollowing(String followerNickName, String followingNickName);


}
