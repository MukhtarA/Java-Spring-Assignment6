package lab6.controller;

import org.springframework.web.bind.annotation.*;
import lab6.dataModel.Request;
import lab6.enums.PostDataForRequest;
import lab6.enums.RequestStatusEnum;
import lab6.service.RequestService;

import java.util.List;

@RestController
@RequestMapping("/requests")
public class RequestController {
    private RequestService requestService;

    @GetMapping("")
    public List<Request> getRequestByMemberLoginAndStatus(
            @RequestParam("memberLogin") String login,
            @RequestParam("status") RequestStatusEnum status
    ) {
        return requestService.getByMemberLoginAndStatus(login, status);
    }

    @GetMapping("/over-due-date")
    public List<Request> getByLastDateLessThan() {
        return requestService.getLastDateLessThan();
    }

    @GetMapping("/over-due-date/{memberLogin}")
    public List<Request> getByMemberLoginAndStatusIsAndLastDateLessThan(@PathVariable("memberLogin") String login) {
        return requestService.getLastDate(login);
    }

    @PostMapping("/create")
    public Request makeNewRequest(@RequestBody PostDataForRequest data) {
        return requestService.makeNewRequest(data.memberLogin, data.bookId);
    }

    @PatchMapping("/update/{id}")
    public Request changeRequestStatus(@PathVariable("id") Long id, @RequestParam("status") RequestStatusEnum status) {
        if (status == RequestStatusEnum.ISSUE) {
            return requestService.changeStatusToIssue(id);
        }
        return requestService.changeStatusToReturn(id);
    }
}
