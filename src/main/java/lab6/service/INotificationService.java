package lab6.service;

import lab6.dataModel.Notification;
import lab6.enums.NotificationStatusEnum;

import java.util.List;

public interface INotificationService {
    void saveNotification(Notification notification);
    int getUnreadNotificationSizeByMemberLogin(String login);
    List<Notification> getByMemberLoginAndStatus(String login, NotificationStatusEnum status);
    void saveAll(List<Notification> notifications);
}
