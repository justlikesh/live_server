package com.ssafy.fitcha.model.service;

import java.util.List;
import java.util.Map;

import org.springframework.stereotype.Service;

import com.ssafy.fitcha.model.dao.UserDao;
import com.ssafy.fitcha.model.dto.User;

@Service
public class UserServiceImpl implements UserService {

	// 생성자 의존성 주입
	private final UserDao userDao;

	public UserServiceImpl(UserDao userDao) {
		this.userDao = userDao;
	}

	// 유저 회원가입
	@Override
	public boolean registUser(User user) {

		return 1 == userDao.insertUser(user);
	}

	// 유저 탈퇴
	@Override
	public boolean deleteUser(int userBoardId) {
		return 1 == userDao.deleteUser(userBoardId);
	}

	// 유저 로그인
	@Override
	public User login(User user) {
		// 로그인 요청 받은 id와 일치한 registedUser 반환
		// 일치한게 없다면 null이다.
		User registedUser = userDao.selectRegistedUser(user);
		if (registedUser != null) {
			return registedUser;
		}
		return null;
	}
	
	// 유저 팔로우 
	@Override
	public boolean follow(String followerNickName, String followingNickName) {
		
		return 1 == userDao.insertFollowUser(followerNickName, followingNickName);
	}
	
	// 유저 언팔로우 
	@Override
	public boolean unfollow(String followerNickName, String followingNickName) {
		
		return 1 == userDao.deleteFollowUser(followerNickName, followingNickName);
	}

	// 유저 팔로우, 팔로잉 전체 수 조회 
	@Override
	public Map<String, Integer> getFollowAllCount(String nickName) {
		return userDao.selectFollowCount(nickName);
	}
	
	// 유저 팔로워 전체 조회 
	@Override
	public List<String> getFollowerAllList(String userNickName) {
		return userDao.selectFollowerAll(userNickName);
	}
	
	// 유저 팔로잉 전체 조회 
	@Override
	public List<String> getFollowingAllList(String userNickName) {
		return userDao.selectFollowingAll(userNickName);
	}
	
	// 유저 정보 조회 
	@Override
	public User getUserInfo(String userNickName) {
		return userDao.selectUser(userNickName);
	}
	
	// 유저 정보 수정
	@Override
	public boolean updateUserInfo(User user) {
		
		return userDao.updateUser(user);
	}

	// 상대방 팔로우 하는지 체크
	@Override
	public boolean isFollowing(String followerNickName, String followingNickName) {
		return userDao.selectFollowCheck(followerNickName,followingNickName);
	}
	
	
	
	

}
