package seo.study.springsecurity.common;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;
import seo.study.springsecurity.account.Account;
import seo.study.springsecurity.account.AccountService;
import seo.study.springsecurity.book.Book;
import seo.study.springsecurity.book.BookRepository;

@Component
public class DefaultDataGenerator implements ApplicationRunner {

    @Autowired
    AccountService accountService;

    @Autowired
    BookRepository bookRepository;

    @Override
    public void run(ApplicationArguments args) throws Exception {
        Account account1 = createUser("test user");
        Account account2 = createUser("test user2");
        createBook("test book1",account1);
        createBook("test book2",account2);
    }

    private void createBook(String title, Account account) {
        Book book = new Book();
        book.setTitle(title);
        book.setAuthor(account);
        bookRepository.save(book);
    }

    private Account createUser(String  username) {

        Account account = new Account();
        account.setUsername(username);
        account.setPassword("123");
        account.setRole("USER");
        return accountService.createNew(account);
    }

}
