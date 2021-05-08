package lab6.service;

import lab6.dataModel.Book;

import java.util.List;

public interface IBookService {
    List<Book> getAll();
    Book getBookById(Long id);
    List<Book> getBooksByName(String name, String author, String description);
}
