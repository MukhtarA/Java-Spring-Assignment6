package lab6.controller;

import org.springframework.stereotype.Controller;
import lab6.dataModel.Notification;
import lab6.enums.NotificationStatusEnum;
import lab6.service.NotificationService;

import java.util.List;

@Controller
public class NotificationController {
    private NotificationService notificationService;

    public void saveNotification(Notification notification) {
        notificationService.saveNotification(notification);
    }

    public int getCountUnreadByMember_Login(String login) {
        return notificationService.getUnreadNotificationSizeByMemberLogin(login);
    }

    public List<Notification> getByMemberLoginAndStatus(String login, NotificationStatusEnum status) {
        return notificationService.getByMemberLoginAndStatus(login, status);
    }

}
