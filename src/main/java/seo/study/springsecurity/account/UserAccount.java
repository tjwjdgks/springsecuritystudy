package seo.study.springsecurity.account;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;
import java.util.List;

// Argument resolver, @AuthenticationPrincipal example
public class UserAccount extends User {
    private Account account;
    public UserAccount(Account account) {

        super(account.getUsername(), account.getPassword(), List.of(new SimpleGrantedAuthority("ROLE_"+ account.getRole())));
        this.account = account;

    }

    public Account getAccount() {
        return account;
    }
}
