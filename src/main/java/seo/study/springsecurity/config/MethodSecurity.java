package seo.study.springsecurity.config;


import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.RoleHierarchyVoter;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;

// method security 예제
// spring security가 spring aop를 사용해서 bean에다 @Secured()가 붙어 있는 것 적절한 처리를 해준다
@Configuration
// argument에 true 값을 줌으로써 사용할 annotation을 선택 할 수 있다.
@EnableGlobalMethodSecurity(securedEnabled = true,prePostEnabled = true, jsr250Enabled = true)
// MethodSecurity용 계층형 role 만드는 방법
public class MethodSecurity extends GlobalMethodSecurityConfiguration {
    @Override
    protected AccessDecisionManager accessDecisionManager() {
        RoleHierarchyImpl roleHierarchy  = new RoleHierarchyImpl();
        roleHierarchy.setHierarchy("ROLE_ADMIN > ROLE_USER");

        AffirmativeBased accessDecisionManager = (AffirmativeBased) super.accessDecisionManager();
        accessDecisionManager.getDecisionVoters().add(new RoleHierarchyVoter(roleHierarchy));
        return accessDecisionManager;
    }

}
