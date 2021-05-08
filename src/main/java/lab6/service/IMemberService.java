package lab6.service;

import lab6.dataModel.Member;

import java.util.List;

public interface IMemberService {
    boolean checkByLoginAndPassword(String login, String password);
    Member getByLogin(String login);
    List<Member> getAll();
    Member saveMember(Member member);
    Member createMember(Member member);
}
