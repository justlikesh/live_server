package com.ssafy.fitcha.util;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

import org.springframework.stereotype.Component;

@Component
public class DBUtil {
	private final String url = "jdbc:mysql://localhost:3306/fitcha?serverTimezone=UTC";
	private final String username = "ssafy";
	private final String password = "ssafy";
	private final String driverName = "com.mysql.cj.jdbc.Driver";

    public DBUtil() {
        // JDBC 드라이버를 로딩한다. 드라이버 로딩은 객체 생성 시 한번만 진행하도록 하자.
        try {
            Class.forName(driverName);
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }

    public Connection getConnection() throws SQLException{
    	return DriverManager.getConnection(url, username, password);
    }
}