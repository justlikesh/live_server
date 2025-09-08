package com.ssafy.fitcha.config;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.context.annotation.Configuration;
@Configuration
@MapperScan(basePackages = "com.ssafy.fitcha.model.dao")
public class DBConfig {

}
