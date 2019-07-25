package com.studyssm.controller;

import com.studyssm.entity.User;
import com.studyssm.service.UserService;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;


/**
 * Describe:
 *
 * @author cwqsolo
 * @date 2019/07/24
 */
@Controller
@RequestMapping("user")
public class UserController {
    @Autowired
    UserService userSer;

    User user;

    /**
     * @param
     * @return
     * @todo 用户登录
     * @since 获取当前用户，
     * 判断用户是否已经认证登录，
     * 用账号密码创建UsernamePasswordToken，
     * 调用subject的login方法
     */

    @RequestMapping(method = RequestMethod.POST, value = "logon")
    public String logon(@RequestParam("username") String username, @RequestParam("password") String password) {
        //创建Subject实例对象
        Subject subject = SecurityUtils.getSubject();
        //判断当前用户是否已登录
        if (subject.isAuthenticated() == false) {
            UsernamePasswordToken token = new UsernamePasswordToken(username, password);
            try {
                subject.login(token);
                System.out.println("UserController logon ++++++");
            } catch (AuthenticationException e) {
                e.getMessage();
                e.printStackTrace();
                System.out.println("登录失败");
                return "redirect:/login.jsp";
            }
        }
        return "redirect:/index.jsp";
    }

    @RequestMapping(method = RequestMethod.POST, value = "logout")
    public String logout( ) {
        //创建Subject实例对象
        Subject subject = SecurityUtils.getSubject();
        //判断当前用户是否已登录
        if (subject.isAuthenticated() == false) {
            //退出登录
            subject.logout();
            System.out.println("subject.logout!!!");
        }
        return "redirect:/login.jsp";
    }

}
