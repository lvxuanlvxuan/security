package com.zimug.courses.security.basic;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootTest
class BasicServerApplicationTests {

	@Test
	void contextLoads() {
	}

	@Test
	void bCryptPasswordTest(){
		PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
		String password = "123456";
		String encode = passwordEncoder.encode(password);

		System.out.println("原始密码："+password);
		System.out.println("加密后的密码："+encode);

		System.out.println(password+"是否匹配"+encode+":"+passwordEncoder.matches(password,encode));

		System.out.println("654321是否配置"+encode+":"+passwordEncoder.matches("654321",encode));
	}
}
