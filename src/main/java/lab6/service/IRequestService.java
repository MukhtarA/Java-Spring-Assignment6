package lab6.service;

import lab6.dataModel.Request;
import lab6.enums.RequestStatusEnum;

import java.util.List;

public interface IRequestService {
    Request makeNewRequest(String login, Long bookId);
    List<Request> getByMemberLoginAndStatus(String login, RequestStatusEnum status);
    List<Request> getLastDate(String login);
    List<Request> getLastDateLessThan();
    List<Request> getByStatus(RequestStatusEnum status);
}
