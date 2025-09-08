package com.ssafy.fitcha.model.service;

import java.io.File;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import com.ssafy.fitcha.model.dao.FileDao;
import com.ssafy.fitcha.model.dto.ChallengeFile;
import com.ssafy.fitcha.model.dto.ProofFile;

@Service
public class FileServiceImpl implements FileService {
	@Value("${challenge.file.upload-dir}")
	private String uploadDirPath;
	@Value("${proof.file.upload-dir}")
	private String uploadDirPathProof;
	@Value("${user.file.upload-dir}")
	private String uploadDirPathUser;

	private FileDao fileDao;
	private ResourceLoader resourceLoader;

	public FileServiceImpl(FileDao fileDao, ResourceLoader resourceLoader) {
		this.fileDao = fileDao;
		this.resourceLoader = resourceLoader;
	}

	// 챌린지파일 목록 조회
	@Override
	public List<ChallengeFile> getChallengeFileList(int challengeBoardId) {
		return fileDao.selectChallengeFileList(challengeBoardId);
	}

	// 챌린지 파일 리스트 삭제
	@Override
	public void deleteChallengeFile(List<Integer> deleteChallengeFileIds) {
		for (int challengeFileId : deleteChallengeFileIds) {
			fileDao.deleteChallengeFile(challengeFileId);
		}

	}

	// 챌린지 파일 등록
	@Override
	public void insertChallengeFile(List<MultipartFile> files, int challengeBoardId, String writer) throws Exception {
		if (files == null || files.isEmpty()) {
			return;
		}

		File uploadDir = new File(uploadDirPath);
		if (!uploadDir.exists()) {
			uploadDir.mkdirs();
		}

		for (MultipartFile file : files) {
			if (!file.isEmpty()) {
				String originalFileName = file.getOriginalFilename();
				String uploadFileName = generateUniqueName(originalFileName);
				file.transferTo(new File(uploadDir, uploadFileName));

				ChallengeFile challengeFile = new ChallengeFile();
				challengeFile.setChallengeBoardId(challengeBoardId);
				challengeFile.setFileOriginalName(originalFileName);
				challengeFile.setFileUploadName(uploadFileName);
				challengeFile.setFileUrl("upload/" + uploadFileName); // 경로 저장
				challengeFile.setWriter(writer);

				fileDao.insertChallengeFile(challengeFile);
			}
		}
	}

	// ---------------------------------인증글
	// 파일--------------------------------------------

	// 인증글 파일 목록 조회
	@Override
	public List<ProofFile> getProofFileList(int proofBoardId) {
		return fileDao.selectProofFileList(proofBoardId);
	}

	// 인증글 파일 삭제
	@Override
	public void deleteProofFile(List<Integer> deleteProofFileIds) {
		for (int proofFileId : deleteProofFileIds) {
			fileDao.deleteProofFile(proofFileId);
		}
	}

	// 인증글 파일 등록
	@Override
	public void insertProofFile(List<MultipartFile> files, int proofBoardId, String writer) throws Exception {
		if (files == null || files.isEmpty()) {
			return;
		}

		File uploadDir = new File(uploadDirPathProof);
		if (!uploadDir.exists()) {
			uploadDir.mkdirs();
		}

		for (MultipartFile file : files) {
			if (!file.isEmpty()) {
				String originalFileName = file.getOriginalFilename();
				String uploadFileName = generateUniqueName(originalFileName);
				file.transferTo(new File(uploadDir, uploadFileName));

				ProofFile proofFile = new ProofFile();
				proofFile.setProofBoardId(proofBoardId);
				proofFile.setFileOriginalName(originalFileName);
				proofFile.setFileUploadName(uploadFileName);
				proofFile.setFileUrl("upload/" + uploadFileName); // 경로 저장
				proofFile.setWriter(writer);

				fileDao.insertProofFile(proofFile);
			}
		}
	}

	// 인증글 파일 수정
	@Override
	public void updateProofFile(List<MultipartFile> files, int proofBoardId, String writer)
			throws IllegalStateException, IOException {
		if (files == null || files.isEmpty()) {
			return;
		}

		File uploadDir = new File(uploadDirPathProof);
		if (!uploadDir.exists()) {
			uploadDir.mkdirs();
		}
		for (MultipartFile file : files) {
			if (!file.isEmpty()) {
				String originalFileName = file.getOriginalFilename();
				String uploadFileName = generateUniqueName(originalFileName);
				file.transferTo(new File(uploadDir, uploadFileName));

				ProofFile proofFile = new ProofFile();
				proofFile.setProofBoardId(proofBoardId);
				proofFile.setFileOriginalName(originalFileName);
				proofFile.setFileUploadName(uploadFileName);
				proofFile.setFileUrl("upload/" + uploadFileName); // 경로 저장
				proofFile.setWriter(writer);

				fileDao.updateProofFile(proofFile);
			}
		}
	}

	// 유저 이미지 파일 수정
	@Override
	public String updateUserFile(MultipartFile profileImgUrl) throws IOException {
		if (profileImgUrl == null || profileImgUrl.isEmpty()) {
			return null;
		}

		File uploadDir = new File(uploadDirPathUser);
		if (!uploadDir.exists()) {
			uploadDir.mkdirs();
		}

		String originalFileName = profileImgUrl.getOriginalFilename();
		String uploadFileName = generateUniqueName(originalFileName);
		File destFile = new File(uploadDir, uploadFileName);

		profileImgUrl.transferTo(destFile);

		// 반환하는 URL은 클라이언트가 접근 가능한 경로를 기준으로 설정
		// 예: "/upload/user/" + uploadFileName 또는 uploadDirPathUser + uploadFileName
		// uploadDirPathUser가 절대경로면 상대경로로 바꿔야 할 수도 있음

		String fileUrl = "upload/" + uploadFileName;

		return fileUrl;
	}

	// 유니크 네임 생성 함수
	private String generateUniqueName(String originalName) {
		String timeStr = new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date());
		String uuid = UUID.randomUUID().toString().substring(0, 8);
		String ext = "";

		int idx = originalName.lastIndexOf('.');
		if (idx != -1) {
			ext = originalName.substring(idx);
		}

		return timeStr + "_" + uuid + ext;
	}

}
