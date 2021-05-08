package lab6.controller;

import org.springframework.web.bind.annotation.*;
import lab6.dataModel.Member;
import lab6.service.MemberService;

import java.util.List;

@RestController
@RequestMapping("/members")
public class MemberController {
    private MemberService memberService;

    @GetMapping("")
    public List<Member> getAllMembers() {
        return memberService.getAll();
    }

    @GetMapping("/hello")
    public String getHello() {
        return "Hello World!";
    }

    @PostMapping("/create")
    public Member createNewMember(@RequestBody Member member) {
        return memberService.createMember(member);
    }
}
