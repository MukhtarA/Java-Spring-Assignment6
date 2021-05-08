package lab6.service;

import lab6.dataModel.Collection;

import java.util.List;

public interface ICollectionService {
    List<Collection> getAll();
    Collection getById(Long id);
    Collection save(Collection collection);
    void delete(Long id);
}
