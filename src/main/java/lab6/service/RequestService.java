package lab6.service;

import org.springframework.stereotype.Service;
import lab6.dataModel.Book;
import lab6.dataModel.Member;
import lab6.dataModel.Notification;
import lab6.dataModel.Request;
import lab6.enums.RequestStatusEnum;
import lab6.repo.RequestR;

import java.util.Date;
import java.util.List;

@Service
public class RequestService implements IRequestService {
    private RequestR requestR;
    private BookService bookService;
    private MemberService memberService;
    private NotificationService notificationService;

    @Override
    public Request makeNewRequest(String login, Long bookId) {
        Request request = new Request();
        Book book = bookService.getBookById(bookId);
        Member member = memberService.getByLogin(login);
        return requestR.saveAndFlush(request);
    }

    @Override
    public List<Request> getByMemberLoginAndStatus(String login, RequestStatusEnum status) {
        return requestR.getRequestByMember(login, status);
    }

    @Override
    public List<Request> getLastDate(String login) {
        return requestR.getRequestsByMember(login, RequestStatusEnum.ISSUE, new Date());
    }

    @Override
    public List<Request> getLastDateLessThan() {
        return requestR.getRequestsByStatus(RequestStatusEnum.ISSUE, new Date());
    }

    @Override
    public List<Request> getByStatus(RequestStatusEnum status) {
        return requestR.getRequestByStatus(status);
    }

    public Request changeStatusToIssue(Long id) {
        Request request = requestR.getRequestById(id);

        Date date = new Date();
        request.setIssuedDate(date);

        Date lasDay = new Date(request.getIssuedDate().getTime() + (60 * 60 * 24 * 14 * 1000));
        request.setLastDate(lasDay);


        Notification notification = new Notification();
        notification.setDate(date);
        String message = "Your issue request(id=" + request.getId() + ") was accepted!";
        notification.setMessage(message);
        notificationService.saveNotification(notification);

        return requestR.saveAndFlush(request);
    }

    public Request changeStatusToReturn(Long id) {
        Request request = requestR.getRequestById(id);

        Date date = new Date();
        request.setReturnDate(date);

        Notification notification = new Notification();
        notification.setDate(date);
        String message = "Your return request(id=" + request.getId() + ") was accepted!";
        notification.setMessage(message);
        notificationService.saveNotification(notification);

        return requestR.saveAndFlush(request);
    }
}
