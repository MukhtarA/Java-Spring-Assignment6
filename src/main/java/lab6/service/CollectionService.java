package lab6.service;

import org.springframework.stereotype.Service;
import lab6.dataModel.Collection;
import lab6.repo.CollectionR;

import java.util.List;

@Service
public class CollectionService implements ICollectionService {
    private CollectionR collectionR;

    @Override
    public List<Collection> getAll() {
        return collectionR.getCollectionsBy();
    }

    @Override
    public Collection getById(Long id) {
        return collectionR.getCollectionById(id);
    }

    @Override
    public Collection save(Collection collection) {
        return collectionR.saveAndFlush(collection);
    }

    @Override
    public void delete(Long id) {
        collectionR.deleteById(id);
    }
}
