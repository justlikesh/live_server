package com.ssafy.fitcha.model.service;

import java.util.Random;

import org.springframework.stereotype.Service;

import com.ssafy.fitcha.model.dao.UserDao;

@Service
//@RequiredArgsConstructor
public class NicknameService {

	private UserDao userDao;

	public NicknameService(UserDao userDao) {
		this.userDao = userDao;
	}

	private final Random random = new Random();

	private static final String[] ADJECTIVES = { "행복한", "슬기로운", "용감한", "빠른", "귀여운", "똑똑한", "재치있는", "친절한", "멋진", "따뜻한",
			"순수한", "엉뚱한", "우아한", "반짝이는", "창의적인", "유쾌한", "상냥한", "든든한", "명랑한", "기발한", "배려하는", "활발한", "조용한", "빛나는", "달콤한",
			"섬세한", "놀라운", "진지한", "신비로운", "열정적인" };

	private static final String[] NOUNS = { "호랑이", "토끼", "독수리", "곰", "여우", "고양이", "강아지", "펭귄", "사슴", "늑대", "부엉이", "기린",
			"코끼리", "원숭이", "수달", "거북이", "햄스터", "판다", "사자", "돌고래", "하마", "양", "말", "치타", "앵무새", "돼지", "두더지", "다람쥐", "오리",
			"고래", "햇살", "달빛", "바람", "하늘", "구름", "비", "눈송이", "파도", "별빛", "아침", "저녁", "커피", "초코", "빵", "노래", "춤", "산책",
			"휴식", "운동", "여행", "마법", "웃음", "모험", "빛" };

	private static final char[] SUFFIXES = "abcdefghijklmnopqrstuvwxyz".toCharArray();

	public String generateUniqueNickname() {
		String base = generateBaseNickname();

		// 우선 접미사 없이 시도
		if (!isDuplicate(base)) {
			return base;
		}

		// 접미사 붙이기 (a~z)
		for (char suffix : SUFFIXES) {
			String nicknameWithSuffix = base + suffix;
			if (!isDuplicate(nicknameWithSuffix)) {
				return nicknameWithSuffix;
			}
		}

		// 그래도 중복되면 무작위 숫자 추가 (fallback)
		int retry = 1;
		String fallback;
		do {
			fallback = base + retry++;
		} while (isDuplicate(fallback));

		return fallback;
	}

	private String generateBaseNickname() {
		String adjective = ADJECTIVES[random.nextInt(ADJECTIVES.length)];
		String noun = NOUNS[random.nextInt(NOUNS.length)];
		return adjective + noun;
	}

	public boolean isDuplicate(String nickname) {
		return userDao.existsByNickname(nickname) == 1;
	}
}