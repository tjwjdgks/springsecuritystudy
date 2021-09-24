package seo.study.springsecurity.form;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.test.context.support.WithMockUser;
import seo.study.springsecurity.account.Account;
import seo.study.springsecurity.account.AccountService;

import static org.junit.jupiter.api.Assertions.*;

// 메소드 시큐리티 test
@SpringBootTest
class SampleServiceTest {

    @Autowired
    SampleService sampleService;

    @Autowired
    AccountService accountService;

    @Autowired
    AuthenticationManager authenticationManager;


    @Test
    //@WithMockUser // 아래의 검증 코드 생략가능 // 임의의 user가 인증되어 있다고 가정
    public void dashboard(){
        Account account = new Account();
        account.setRole("USER");
        account.setUsername("seo");
        account.setPassword("123");
        accountService.createNew(account);

        UserDetails userDetails = accountService.loadUserByUsername("seo");


        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(userDetails,"123");
        // 인증된 authenticate
        Authentication authenticate = authenticationManager.authenticate(token);

        SecurityContextHolder.getContext().setAuthentication(authenticate);
        sampleService.dashboard();
    }

}