package lab6.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import lab6.dataModel.Notification;
import lab6.enums.NotificationStatusEnum;
import lab6.repo.NotificationR;

import java.util.List;

@Service
public class NotificationService implements INotificationService {
    @Autowired
    private NotificationR notificationR;

    @Override
    public void saveNotification(Notification notification) {
        notificationR.save(notification);
    }

    @Override
    public int getUnreadNotificationSizeByMemberLogin(String login) {
        return notificationR.countNotifications(login, NotificationStatusEnum.UNREAD);
    }

    @Override
    public List<Notification> getByMemberLoginAndStatus(String login, NotificationStatusEnum status) {
        return notificationR.getNotifications(login, status);
    }

    @Override
    public void saveAll(List<Notification> notifications) {
        notificationR.saveAll(notifications);
    }
}
