package lab6.repo;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import lab6.dataModel.Book;

import java.util.List;

@Repository
public interface BookR extends JpaRepository<Book, Long> {
    List<Book> getBooksBy();
    Book getBookById(Long id);
    List<Book> getBookByName(String name, String author, String description);
}
