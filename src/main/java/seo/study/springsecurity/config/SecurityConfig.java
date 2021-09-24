package seo.study.springsecurity.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.access.expression.WebExpressionVoter;
import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter;
import seo.study.springsecurity.account.AccountService;
import seo.study.springsecurity.common.LoggingFilter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

// 설정 custom
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    // 명시적으로 하는 방법
    @Autowired
    AccountService accountService;

    //AccessDecisionManager 커스터마이징 // 계층형 role 만드는 방법
    public AccessDecisionManager accessDecisionManager(){
        // handler setting
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        roleHierarchy.setHierarchy("ROLE_ADMIN > ROLE_USER");

        DefaultWebSecurityExpressionHandler handler = new DefaultWebSecurityExpressionHandler();
        handler.setRoleHierarchy(roleHierarchy);

        WebExpressionVoter webExpressionVoter = new WebExpressionVoter();
        webExpressionVoter.setExpressionHandler(handler);

        List<AccessDecisionVoter<? extends Object>> voters = Arrays.asList(webExpressionVoter);
        return new AffirmativeBased(voters);
    }

    // expression handler 커스터 마이징
    public SecurityExpressionHandler accessDecisionHandler(){

        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        roleHierarchy.setHierarchy("ROLE_ADMIN > ROLE_USER");

        DefaultWebSecurityExpressionHandler handler = new DefaultWebSecurityExpressionHandler();
        handler.setRoleHierarchy(roleHierarchy);

        return handler;
    }
    // 특정 자원에 security 적용하고 싶지 않을 때 사용
    // 정적인 resource 사용 권장
    @Override
    public void configure(WebSecurity web) throws Exception {
        // ignore 가능
        //web.ignoring().mvcMatchers("/favicon.ico");

        // spring boot static resource 무시
        web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }
    // 동적 resource 사용 권장
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // custom 필터 끼워 넣기
        http.addFilterBefore(new LoggingFilter(), WebAsyncManagerIntegrationFilter.class);
        http.authorizeRequests()
                .mvcMatchers("/","/info","/account/**","/signup").permitAll()
                .mvcMatchers("/admin").hasRole("ADMIN")
                .mvcMatchers("/user").hasRole("USER")
                .anyRequest().authenticated()
                //.accessDecisionManager(accessDecisionManager()) // manager 쓰는 경우
                .expressionHandler(accessDecisionHandler()); // handler 쓰는 경우
        // 로그인 page 커스터 마이징
        http.formLogin()
                .loginPage("/login")// <- url로 로그인 사용자 커스터 마이징 page 보여주는 것 get 요청만, post 요청은 UsernamePasswordAuthenticationFilter 담당
                .defaultSuccessUrl("/")
                .permitAll();
        http.httpBasic();
        // http LogoutFilter 확인해보기
        http.logout()
                .logoutSuccessUrl("/"); // logout 성공시 direct page default는 login
                 //.logoutUrl("/logout") // logout을 하는 url mapping default logout
                 // logoutSuccessHandler, addLogoutHandler 등 handler 구현 가능
                 // 쿠키 기반의 로그인 방식일 때 deleteCookies()

        // 인가 예외 처리 page custom
        http.exceptionHandling()
                .accessDeniedPage("/access-denied");
        // accessDeniedHandler 더 많은 기능 지원
        // SecurityContextHolder 전략 바꿈,  MODE_INHERITABLETHREADLOCAL는 하위 thread는 security context 공유
        /*
        // 클래스로 빼는 것이 좋음
        http.exceptionHandling().accessDeniedHandler(new AccessDeniedHandler() {
            @Override
            public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
                UserDetails principal = (UserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
                String username = principal.getUsername();
                System.out.println(username); // logger 쓰는 것이 좋음
            }
        });

        */

        // rememberMe token 확인
        // default는 remember-me // rememberMeParameter RememberMeServices에서 rememberMeParameter로 검증
        // rememberMe로 session을 만들어 준다
        http.rememberMe()
                .userDetailsService(accountService)
                .key("remember-me-sample");

        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);

    }



    // user 정보 설정 가능
    /*
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // 기존 password encoder 인코딩 방식 prefix로 암호화 한다 {noop}은 인코딩 안함

        auth.inMemoryAuthentication()
                .withUser("seo")
                .password("{noop}123")
                .roles("USER");

        auth.inMemoryAuthentication()
                .withUser("admin")
                .password("{noop}!@#").roles("ADMIN");
    }

     */

    // 명시적으로 하는 방법
    // UserDetailsService가 bean으로 등록되어 있으면 자동으로 설정 해준다
    /*
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(accountService);
    }

     */
    // password 기본 전략을 바꿨다
    @Bean
    public PasswordEncoder passwordEncoder(){
        // 권장 x
        // return NoOpPasswordEncoder.getInstance();

        // 권장
        // default bcrypt
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    // (SampleServiceTest) test를 위해 authenticationManager bean으로 등록해서 노출 시킨다

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
