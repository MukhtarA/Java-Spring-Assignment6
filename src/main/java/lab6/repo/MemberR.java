package lab6.repo;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import lab6.dataModel.Member;

import java.util.List;

@Repository
public interface MemberR extends JpaRepository<Member, Long> {
    boolean existsMember(String login, String password);
    Member getMemberByLogin(String login);
    Member findByLogin(String login);
    List<Member> getMembersBy();
}
