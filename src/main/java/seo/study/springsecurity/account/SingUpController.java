package seo.study.springsecurity.account;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;


//CSRF 토큰 사용 예제
// 자동으로 토큰 넣어준다
@Controller
@RequestMapping("/signup")
public class SingUpController {

    @Autowired
    AccountService accountService;

    @GetMapping
    public String signupForm(Model model){
        model.addAttribute("account", new Account());
        return "signup";
    }

    @PostMapping
    public String processSignUp(@ModelAttribute Account account){
        account.setRole("USER");
        accountService.createNew(account);
        return "redirect:/";
    }

}
