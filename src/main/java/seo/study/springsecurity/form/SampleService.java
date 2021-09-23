package seo.study.springsecurity.form;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import seo.study.springsecurity.account.Account;
import seo.study.springsecurity.account.AccountContext;

import java.util.Collection;

@Service
public class SampleService {

    public void dashboard() {
        /*
        // 어떻게 인증되는 지 알기위해 debug 용
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Object principal = authentication.getPrincipal(); // 사실상 UserDetail type // 사용자를 나타는 것
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();// 사용자의 권한을 나타내는 것
         */
        // Thread Local 확인
        Account account = AccountContext.getAccount();
        System.out.println("====================");
        System.out.println(account.getUsername());
    }
}
