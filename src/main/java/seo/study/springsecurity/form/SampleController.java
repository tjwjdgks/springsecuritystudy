package seo.study.springsecurity.form;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import seo.study.springsecurity.account.AccountContext;
import seo.study.springsecurity.account.AccountRepository;
import seo.study.springsecurity.account.UserAccount;
import seo.study.springsecurity.book.BookRepository;
import seo.study.springsecurity.common.SecurityLogger;

import java.security.Principal;
import java.util.concurrent.Callable;

@Controller
public class SampleController {

    @Autowired
    SampleService sampleService;

    @Autowired
    AccountRepository accountRepository;

    @Autowired
    BookRepository bookRepository;

    // @AuthenticationPrincipal example
    @GetMapping("/")
    //public String index(Model model, @CurrentUser Account account){ // 에노테이션 방법
    public String index(Model model, @AuthenticationPrincipal UserAccount userAccount){
        if(userAccount == null){
            model.addAttribute("message", "Hello spring security");
        }
        else{
            model.addAttribute("message", "Hello " + userAccount.getUsername());
        }
        return "index";
    }
    @GetMapping("/info")
    public String info(Model model){
        model.addAttribute("message", "Hello spring security");
        return "info";
    }
    @GetMapping("/dashboard")
    public String dashBoard(Model model, Principal principal){
        model.addAttribute("message", "Hello " + principal.getName());
        AccountContext.setAccount(accountRepository.findByUsername(principal.getName()));
        sampleService.dashboard();
        return "dashboard";
    }
    @GetMapping("/admin")
    public String admin(Model model, Principal principal){
        model.addAttribute("message", "Hello Admin, " + principal.getName());
        return "admin";
    }
    @GetMapping("/user")
    public String user(Model model, Principal principal){
        model.addAttribute("message", "Hello User, " + principal.getName());
        model.addAttribute("books",bookRepository.findCurrentUserBooks());
        return "user";
    }

    //async
    //WebAsyncManagerIntegrationFilter가 async함에도 security context 공유 할 수 있게 해준다
    @GetMapping("/aysn-handler")
    @ResponseBody
    public Callable<String> asyncHandler(){
        SecurityLogger.log("MVC");
        // request를 처리하고 있는 thread 반환, callable이 하는 일이 완료가 되었을 때 응답을 보낸다
        return new Callable<String>() {
            @Override
            public String call() throws Exception {
                SecurityLogger.log("Callable");
                return "Async Handler";
            }
        };
    }

    // 서비스가 비동기적일 때 security context 정보는?
    @GetMapping("/aysn-handler-service")
    @ResponseBody
    public String asyncServiceHandler(){
         SecurityLogger.log("MVC, before async Service");
         sampleService.asyncService();
        SecurityLogger.log("MVC, after async Service"); // async므로 출력 순서 보장 x
        return "Async Service";
    }
}
