package com.security.inflearnspringsecurity.form;

import com.security.inflearnspringsecurity.account.Account;
import com.security.inflearnspringsecurity.account.AccountContext;
import com.security.inflearnspringsecurity.common.SecurityLogger;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.annotation.security.RolesAllowed;

@Service
public class SampleService {

//    @Secured("ROLE_USER")
//    @RolesAllowed("ROLE_USER")
    @PreAuthorize("hasRole('USER')")
    public void dashboard() {
//        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//        Object principal = authentication.getPrincipal();
//        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
//        boolean authenticated = authentication.isAuthenticated();

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        System.out.println("=========================");
        System.out.println(userDetails.getUsername());
    }

    @Async // Async를 사용하는 곳은 SecurityContextHolder을 공유하지 않음
    public void asyncService() {
        SecurityLogger.log("Async Service");
        System.out.println("Async service is called");
    }
}
