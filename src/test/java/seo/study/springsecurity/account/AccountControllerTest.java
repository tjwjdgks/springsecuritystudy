package seo.study.springsecurity.account;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.test.web.servlet.MockMvc;

import javax.transaction.Transactional;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.anonymous;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class AccountControllerTest {

    @Autowired
    MockMvc mockMvc;

    @Autowired
    AccountService accountService;

    @Test
    public void index_anonymous() throws Exception {
        mockMvc.perform(get("/").with(anonymous()))
                .andDo(print())
                .andExpect(status().isOk());
    }
    @Test
    public void index_user() throws Exception {
        // 가짜 유저가 로그인 한 상태에서 뷰 보는 것
        mockMvc.perform(get("/").with(user("seo").roles("USER")))
                .andDo(print())
                .andExpect(status().isOk());
    }
    @Test
    public void admin_admin() throws Exception {
        // 가짜 유저가 로그인 한 상태에서 뷰 보는 것
        mockMvc.perform(get("/admin").with(user("seo").roles("ADMIN")))
                .andDo(print())
                .andExpect(status().isOk());
    }
    // 에노테이션 방법
    @Test
    @WithAnonymousUser
    public void admin_user() throws Exception {
        // 가짜 유저가 로그인 한 상태에서 뷰 보는 것
        mockMvc.perform(get("/admin"))
                .andDo(print())
                .andExpect(status().isUnauthorized());
    }

    @Test
    //@WithMockUser(username = "seo", roles = "USER")
    @WithUserSeo // custom 에노테이션
    public void dashboard_user() throws Exception {
        // 가짜 유저가 로그인 한 상태에서 뷰 보는 것
        mockMvc.perform(get("/dashboard"))
                .andDo(print())
                .andExpect(status().isOk());
    }

    // form login test
    // return되는 account는 password encoding 상태 이므로 raw password 적어야한다
    @Test
    // 단일 test는 문제가 없지만 test가 여러개일 경우 문제가 생길 수도 있으므로 tranactional을 붙이는 것이 좋음
    // test안에서 기본적으로 transactional 롤백
    @Transactional
    public void login() throws Exception  {
        String username = "seo";
        String password = "123";
        Account user = this.createUser(username, password);
        mockMvc.perform(formLogin().user(user.getUsername()).password(password))
                .andExpect(authenticated());
    }

    private Account createUser(String username, String password) {
        Account account = new Account();
        account.setUsername(username);
        account.setPassword(password);
        account.setRole("USER");
        return accountService.createNew(account);
    }
}