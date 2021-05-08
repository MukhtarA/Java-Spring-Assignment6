package lab6.controller;

import org.springframework.web.bind.annotation.*;
import lab6.dataModel.Book;
import lab6.service.BookService;

import java.util.List;

@RestController
@RequestMapping("/books")
public class BookController {
    private BookService bookService;

    @GetMapping("")
    public List<Book> getAllBooks() {
        return bookService.getAll();
    }

    @GetMapping("/{id}")
    public Book getBookById(@PathVariable("id") Long id) {
        return bookService.getBookById(id);
    }

    @GetMapping("/find")
    public List<Book> getByNameOrAuthorOrDescription(
            @RequestParam("name") String name,
            @RequestParam("author") String author,
            @RequestParam("description") String description)
    {
        return bookService.getBooksByName(name, author, description);
    }
}
