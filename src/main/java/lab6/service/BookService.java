package lab6.service;

import org.springframework.stereotype.Service;
import lab6.dataModel.Book;
import lab6.repo.BookR;

import java.util.List;

@Service
public class BookService implements IBookService {
    private BookR bookR;

    @Override
    public List<Book> getAll() {
        return bookR.getBooksBy();
    }

    @Override
    public Book getBookById(Long id) {
        return bookR.getBookById(id);
    }

    @Override
    public List<Book> getBooksByName(String name, String author, String description) {
        return bookR.getBookByName(name, author, description);
    }

    public void updateBook(Book book) {
        bookR.save(book);
    }

    public void decBookQuantitySave(Book book) {
        book.setQuantity(book.getQuantity() - 1);
        bookR.save(book);
    }

    public void incBookQuantitySave(Book book) {
        book.setQuantity(book.getQuantity() + 1);
        bookR.save(book);
    }
}
