package seo.study.springsecurity.account;


import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.security.Principal;

@Controller
public class AccessDeniedController {

    @GetMapping("/access-denied")
    public String accessDenied(Principal principal, Model model){
        model.addAttribute("name",principal.getName());
        return "access-denied";

    }
    @GetMapping("/access-test")
    public String accessDenied(Model model){
        model.addAttribute("name","test");
        return "access-denied";

    }
}
