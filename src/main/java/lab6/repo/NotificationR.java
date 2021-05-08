package lab6.repo;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import lab6.dataModel.Notification;
import lab6.enums.NotificationStatusEnum;

import java.util.List;

@Repository
public interface NotificationR extends JpaRepository<Notification, Long> {
    Integer countNotifications(String login, NotificationStatusEnum status);
    List<Notification> getNotifications(String login, NotificationStatusEnum status);
}
