package com.ssafy.fitcha.model.dao;

import java.util.List;
import java.util.Map;

import org.apache.ibatis.annotations.Param;

import com.ssafy.fitcha.model.dto.User;

public interface UserDao {
	

	// 유저 회원가입 (등록)
	int insertUser(User user);

	// 유저 탈퇴 (삭제)
	int deleteUser(int userBoardId);

	// 유저 로그인
	User selectRegistedUser(User user);

	// 유저 팔로우
	int insertFollowUser(@Param("followerNickName") String followerNickName,
			@Param("followingNickName") String followingNickName);

	// 유저 언팔로우
	int deleteFollowUser(@Param("followerNickName") String followerNickName,
			@Param("followingNickName") String followingNickName);

	// 유저 팔로우, 팔로잉 전체 수 조회
	Map<String, Integer> selectFollowCount(String nickName);

	// 유저 팔로워 전체 조회
	List<String> selectFollowerAll(String userNickName);

	// 유저 팔로잉 전체 조회
	List<String> selectFollowingAll(String userNickName);

	// 닉네임 존재여부
	int existsByNickname(String nickname);

	// 유저 정보 조회
	User selectUser(String userNickName);
	
	// 유저 정보 수정 
	boolean updateUser(User user);
	
	// 상대방 팔로우 체크
	boolean selectFollowCheck(
	    @Param("followerNickName") String followerNickName,
	    @Param("followingNickName") String followingNickName
	);


}
