package lab6.controller;

import org.springframework.web.bind.annotation.*;
import lab6.dataModel.Book;
import lab6.dataModel.Collection;
import lab6.service.BookService;
import lab6.service.CollectionService;

import java.util.List;

@RestController
@RequestMapping("/collections")
public class CollectionController {
    private CollectionService collectionService;
    private BookService bookService;

    @GetMapping("")
    public List<Collection> getAllCollections() {
        return collectionService.getAll();
    }

    @PostMapping("/create")
    public Collection saveNewCollection(@RequestBody Collection collection) {
        return collectionService.save(collection);
    }

    @PutMapping("/update")
    public Collection putCollection(@RequestBody Collection collection) {
        return collectionService.save(collection);
    }

    @PatchMapping("/{id}")
    public Collection addBookInCollection(@PathVariable("id") Long collectionId, @RequestParam("bookId") Long bookId) {
        Book book = bookService.getBookById(bookId);
        Collection collection = collectionService.getById(collectionId);
        return collectionService.save(collection);
    }

    @DeleteMapping("/{id}")
    public void deleteCollection(@PathVariable Long id) {
        collectionService.delete(id);
    }
}
