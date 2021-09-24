package seo.study.springsecurity.form;

import org.springframework.scheduling.annotation.Async;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import seo.study.springsecurity.account.Account;
import seo.study.springsecurity.account.AccountContext;
import seo.study.springsecurity.common.SecurityLogger;

import javax.annotation.security.RolesAllowed;
import java.util.Collection;

@Service
public class SampleService {

    @Secured("ROLE_USER") // @RolesAllowed("ROLE_USER") 도 가능 // 메소드를 호출하기 이전에 권한 검사를 한다
    //@PreAuthorize("hasRole('USER')") // 메소드 호출 이전 권한 검사
    //@PostAuthorize("hasRole('USER')") // 메소드 호출 이후 RETURN 값으로 인가 할 수 있음
    public void dashboard() {
        /*
        // 어떻게 인증되는 지 알기위해 debug 용
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Object principal = authentication.getPrincipal(); // 사실상 UserDetail type // 사용자를 나타는 것
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();// 사용자의 권한을 나타내는 것
         */
        // Thread Local 확인
        /*
        Account account = AccountContext.getAccount();
        System.out.println("====================");
        System.out.println(account.getUsername());
         */
    }
    // 비동기적 호출
    // @Async를 사용하는 곳은 security context가 공유가 안된다
    // --> SecurityContextHolder 전략을 선택할 수 있다 기본 전략에서 다른 전략으로 바꾼다
    @Async
    public void asyncService() {
        SecurityLogger.log("Async Service");
         System.out.println("Async service is called ");
    }
}
