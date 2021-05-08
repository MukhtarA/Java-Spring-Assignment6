package lab6.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import lab6.dataModel.Member;
import lab6.repo.MemberR;

import java.util.List;

@Service
public class MemberService implements IMemberService, UserDetailsService {
    @Autowired
    private MemberR memberR;

    private BCryptPasswordEncoder passwordEncoder;

    @Override
    public boolean checkByLoginAndPassword(String login, String password) {
        return memberR.existsMember(login, password);
    }

    @Override
    public Member getByLogin(String login) {
        return memberR.getMemberByLogin(login);
    }

    @Override
    public List<Member> getAll() {
        return memberR.getMembersBy();
    }

    @Override
    public Member saveMember(Member member) {
        return memberR.saveAndFlush(member);
    }

    @Override
    public Member createMember(Member member) {
        return member;
    }

    @Override
    public UserDetails loadUserByUsername(String login) throws UsernameNotFoundException {
        Member member = memberR.findByLogin(login);

        if (member == null) {
            throw new UsernameNotFoundException("Member by login=" + login + " not found!");
        }
        return (UserDetails) member;
    }
}
