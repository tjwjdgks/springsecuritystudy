package seo.study.springsecurity.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import seo.study.springsecurity.account.AccountService;

// 설정 custom
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    // 명시적으로 하는 방법
    //@Autowired
    //AccountService accountService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .mvcMatchers("/","/info","/account/**").permitAll()
                .mvcMatchers("/admin").hasRole("ADMIN")
                .anyRequest().authenticated()
                .and()
            .formLogin()
                .and()
            .httpBasic();
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
}
