DROP database IF EXISTS fitcha;
CREATE DATABASE IF NOT EXISTS fitcha;
USE fitcha;
-- user --
CREATE TABLE user_board(
user_board_id INT PRIMARY KEY AUTO_INCREMENT,
user_id VARCHAR(300) NOT NULL UNIQUE, -- 회원가입시 아이디 --
password VARCHAR(300) DEFAULT NULL,
email VARCHAR(300) NOT NULL,
name VARCHAR(300) NOT NULL,
nick_name VARCHAR(300) NOT NULL UNIQUE,
age INT CHECK (age >= 0),
gender VARCHAR(300),
follower_count INT DEFAULT 0 CHECK (follower_count >= 0), -- 팔로우 하는 사람 (나) 
following_count INT DEFAULT 0 CHECK (following_count >= 0), -- 팔로우 당하는 사람 (상대방)
profile_img_url VARCHAR(500) -- 프로필 이미지 경로 저장
);

select * from user_board;

CREATE TABLE user_file(
user_file_id INT PRIMARY KEY AUTO_INCREMENT,
user_board_id INT,
file_upload_name VARCHAR(3000) NOT NULL,
file_original_name VARCHAR(3000) NOT NULL,
file_url VARCHAR(3000) NOT NULL,
CONSTRAINT user_file_pk FOREIGN KEY (user_board_id) REFERENCES user_board (user_board_id)
ON DELETE CASCADE
);


-- challenge--
CREATE TABLE challenge_board(
challenge_board_id INT PRIMARY KEY AUTO_INCREMENT,
user_id VARCHAR(300) ,
title VARCHAR(300) NOT NULL,
content TEXT NOT NULL,
writer VARCHAR(300) NOT NULL,
exercise_type VARCHAR(300) NOT NULL DEFAULT '유산소',
body_part VARCHAR(300) NOT NULL DEFAULT '전신',
`level` VARCHAR(300) NOT NULL DEFAULT '초급',
duration INT NOT NULL,
participant_count INT DEFAULT 1 CHECK (participant_count >= 1 AND participant_count <= 100),
total_participant_count INT DEFAULT 1 CHECK (total_participant_count >= 1 AND total_participant_count <= 100),
view_count INT DEFAULT 0 CHECK(view_count >= 0) ,
like_count INT DEFAULT 0 CHECK(like_count >= 0),
reg_date TIMESTAMP DEFAULT NOW(),
finish BOOLEAN NOT NULL DEFAULT FALSE,
subhead VARCHAR(1000) DEFAULT "",
CONSTRAINT challenge_board_user_pk FOREIGN KEY (user_id) REFERENCES user_board(user_id)
ON DELETE CASCADE
);
CREATE TABLE challenge_file(
challenge_file_id INT PRIMARY KEY AUTO_INCREMENT,
challenge_board_id INT,
file_upload_name VARCHAR(3000) NOT NULL,
file_original_name VARCHAR(3000) NOT NULL,
file_url VARCHAR(3000) NOT NULL,
writer VARCHAR(3000) NOT NULL,
CONSTRAINT challenge_file_pk FOREIGN KEY (challenge_board_id) REFERENCES challenge_board (challenge_board_id)
ON DELETE CASCADE 
);

-- proof --
CREATE TABLE proof_board(
proof_board_id INT PRIMARY KEY AUTO_INCREMENT,
challenge_board_id INT,
user_id VARCHAR(300) ,
title VARCHAR(300) NOT NULL,
content TEXT NOT NULL,
writer VARCHAR(300) NOT NULL,
view_count INT DEFAULT 0 CHECK (view_count >= 0),
like_count INT DEFAULT 0 CHECK (like_count >= 0),
reg_date TIMESTAMP DEFAULT NOW(), 
exercise_type VARCHAR(300) NOT NULL DEFAULT '전체',
body_part VARCHAR(300) NOT NULL DEFAULT '전체',
`level` VARCHAR(300) NOT NULL DEFAULT '초급',
CONSTRAINT proof_board_pk FOREIGN KEY (challenge_board_id) REFERENCES challenge_board (challenge_board_id) 
ON DELETE SET NULL,
CONSTRAINT proof_board_user_pk FOREIGN KEY (user_id) REFERENCES user_board(user_id)
ON DELETE SET NULL
);



CREATE TABLE proof_board_hashtag (
    id INT PRIMARY KEY AUTO_INCREMENT,
    proof_board_id INT,
    hashtag VARCHAR(1000),
    CONSTRAINT fk_proof_board FOREIGN KEY (proof_board_id)
        REFERENCES proof_board(proof_board_id)
        ON DELETE CASCADE
);
select * from proof_board_hashtag;

CREATE TABLE proof_file(
proof_file_id INT PRIMARY KEY AUTO_INCREMENT,
proof_board_id INT,
file_upload_name VARCHAR(3000) NOT NULL,
file_original_name VARCHAR(3000) NOT NULL,
file_url VARCHAR(3000) NOT NULL,
writer VARCHAR(3000) NOT NULL,
CONSTRAINT proof_file_pk FOREIGN KEY (proof_board_id) REFERENCES proof_board (proof_board_id) 
ON DELETE CASCADE 
);

-- comment --
CREATE TABLE challenge_comment (
challenge_comment_id INT PRIMARY KEY AUTO_INCREMENT,
challenge_board_id INT,
user_id VARCHAR(300) ,
content VARCHAR(300) NOT NULL,
writer VARCHAR(300) NOT NULL,
reg_date TIMESTAMP DEFAULT NOW(),
CONSTRAINT challenge_comment_pk FOREIGN KEY (challenge_board_id) REFERENCES challenge_board (challenge_board_id) 
ON DELETE CASCADE ,
CONSTRAINT challenge_comment_user_pk FOREIGN KEY (user_id) REFERENCES user_board(user_id) 
ON DELETE CASCADE 

);

CREATE TABLE proof_comment (
proof_comment_id INT PRIMARY KEY AUTO_INCREMENT,
proof_board_id INT,
user_id VARCHAR(300) ,
content VARCHAR(300) NOT NULL,
writer VARCHAR(300) NOT NULL,
reg_date TIMESTAMP DEFAULT NOW(),
CONSTRAINT proof_comment_pk FOREIGN KEY (proof_board_id) REFERENCES proof_board (proof_board_id)
ON DELETE CASCADE,
CONSTRAINT proof_comment_user_pk FOREIGN KEY (user_id) REFERENCES user_board(user_id)
ON DELETE CASCADE 
);

CREATE TABLE fittube_comment(
comment_id INT PRIMARY KEY AUTO_INCREMENT,
video_id VARCHAR(300),
user_id VARCHAR(300) ,
content VARCHAR(300) NOT NULL,
writer VARCHAR(300) NOT NULL,
reg_date TIMESTAMP DEFAULT NOW()
);

-- 좋아요 -------------------------------------------------

CREATE TABLE challenge_like(
board_id INT,
writer varchar(300),
CONSTRAINT challenge_like_pk FOREIGN KEY (board_id) REFERENCES challenge_board (challenge_board_id)
ON DELETE CASCADE 
);

CREATE TABLE proof_like(
proof_board_id int,
writer varchar(300),
CONSTRAINT proof_like_pk FOREIGN KEY (proof_board_id) REFERENCES proof_board (proof_board_id) 
ON DELETE CASCADE 
);

CREATE TABLE fittube_like(
video_id varchar(300),
writer varchar(300)
);

-- 팔로우 ------------------

CREATE TABLE user_follow (
    follower_nick_name VARCHAR(300),  -- 팔로우하는 사람 (나)
    following_nick_name VARCHAR(300), -- 팔로우당하는 사람 (상대)
    PRIMARY KEY (follower_nick_name, following_nick_name),
    CONSTRAINT fk_follower FOREIGN KEY (follower_nick_name) REFERENCES user_board(nick_name) ON DELETE CASCADE,
    CONSTRAINT fk_following FOREIGN KEY (following_nick_name) REFERENCES user_board(nick_name) ON DELETE CASCADE
);



-------- 메세지 ---
CREATE TABLE message(
message_id INT PRIMARY KEY AUTO_INCREMENT,
sender VARCHAR(300) NOT NULL, -- 보낸 사람 --
recipient VARCHAR(300) NOT NULL, -- 받는 사람 --
title VARCHAR(300) NOT NULL, 
content TEXT NOT NULL,
who_delete VARCHAR(50) DEFAULT 'nobody',
is_read BOOLEAN DEFAULT FALSE -- TRUE = 1, FALSE = 0 으로 저장된다함.. --
);

-- 유저들의 참여중인 챌린지 저장 --
CREATE TABLE participant_challenge(
challenge_board_id INT,
participant VARCHAR(300) NOT NULL 
);

CREATE TABLE chat_room (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
	writer VARCHAR(255) NOT NULL,
    reg_date TIMESTAMP DEFAULT NOW()
    );
    
 

CREATE TABLE chat_message (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    room_id BIGINT NOT NULL,
    sender VARCHAR(255),
    message TEXT,
    timestamp DATETIME,
    FOREIGN KEY (room_id) REFERENCES chat_room(id) ON DELETE CASCADE
);

-- 좋아요 트리거 ---------------------------------------------------
 
DROP TRIGGER IF EXISTS trg_increase_like_count;

DELIMITER $$
DROP TRIGGER IF EXISTS trg_increase_challenge_like_count;
DELIMITER $$
CREATE TRIGGER trg_increase_challenge_like_count
AFTER INSERT ON challenge_like
FOR EACH ROW
BEGIN
  UPDATE challenge_board
  SET like_count = like_count + 1
  WHERE challenge_board_id = NEW.board_id;
END $$
DELIMITER ;


DROP TRIGGER IF EXISTS trg_decrease_challenge_like_count;
DELIMITER $$
CREATE TRIGGER trg_decrease_challenge_like_count
AFTER DELETE ON challenge_like
FOR EACH ROW
BEGIN
  UPDATE challenge_board
  SET like_count = like_count - 1
  WHERE challenge_board_id = OLD.board_id;
END $$
DELIMITER ;


DELIMITER $$
CREATE TRIGGER trg_increase_proof_like_count
AFTER INSERT ON proof_like
FOR EACH ROW
BEGIN UPDATE proof_board
		   SET like_count = like_count+1
		WHERE proof_board_id = New.proof_board_id;
END $$
DELIMITER ;

DELIMITER $$
CREATE TRIGGER trg_decrease_proof_like_count
AFTER DELETE ON proof_like
FOR EACH ROW
BEGIN UPDATE proof_board
		   SET like_count = like_count-1
		WHERE proof_board_id = OLD.proof_board_id;
END $$
DELIMITER ;

-- 팔로우 트리거 ----------------------------------
DROP TRIGGER IF EXISTS trg_increase_follow_count;
DROP TRIGGER IF EXISTS trg_decrease_follow_count;

DELIMITER  $$
CREATE TRIGGER trg_increase_user_follow_count -- 팔로우 시 증가 트리거 
AFTER INSERT ON user_follow
FOR EACH ROW 
BEGIN 
	UPDATE user_board SET following_count = following_count + 1
    WHERE nick_name = NEW.follower_nick_name;
    
    UPDATE user_board SET follower_count = follower_count + 1
    WHERE nick_name = NEW.following_nick_name;
END $$
DELIMITER ;

DELIMITER  $$
CREATE TRIGGER trg_decrease_user_follow_count -- 팔로우 시 감소 트리거 
AFTER DELETE ON user_follow
FOR EACH ROW 
BEGIN 
	UPDATE user_board SET following_count = following_count - 1
    WHERE nick_name = OLD.follower_nick_name;
    
    UPDATE user_board SET follower_count = follower_count - 1
    WHERE nick_name = OLD.following_nick_name;
END $$
DELIMITER ;


select * from participant_challenge;
select * from challenge_board;
select * from user_board;
select * from fittube_comment;
select * from challenge_like;
SELECT * FROM chat_room;
select * from chat_message;
select * from user_board;
select * from chat_room;
