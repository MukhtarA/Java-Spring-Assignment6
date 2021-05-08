package lab6.repo;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import lab6.dataModel.Request;
import lab6.enums.RequestStatusEnum;

import java.util.Date;
import java.util.List;

@Repository
public interface RequestR extends JpaRepository<Request, Long> {
    List<Request> getRequestByMember(String login, RequestStatusEnum status);
    List<Request> getRequestsByMember(String login, RequestStatusEnum status, Date date);
    List<Request> getRequestsByStatus(RequestStatusEnum status, Date date);
    List<Request> getRequestByStatus(RequestStatusEnum status);
    Request getRequestById(Long id);
}
