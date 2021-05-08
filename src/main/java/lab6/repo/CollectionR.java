package lab6.repo;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import lab6.dataModel.Collection;

import java.util.List;

@Repository
public interface CollectionR extends JpaRepository<Collection, Long> {
    List<Collection> getCollectionsBy();
    Collection getCollectionById(Long id);
}
