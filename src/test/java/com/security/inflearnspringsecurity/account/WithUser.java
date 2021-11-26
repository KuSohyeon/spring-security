package com.security.inflearnspringsecurity.account;

import org.springframework.security.test.context.support.WithMockUser;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

@Retention(RetentionPolicy.RUNTIME)
@WithMockUser(username = "sohyun", roles = "USER")
public @interface WithUser {
}
