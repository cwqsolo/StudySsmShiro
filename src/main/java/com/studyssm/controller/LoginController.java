package com.studyssm.controller;

import com.studyssm.entity.User;
import com.studyssm.service.UserService;


import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Describe:
 *
 * @author cwqsolo
 * @date 2019/07/22
 */

@Controller
@RequestMapping("")
public class LoginController {
    @Autowired
    private UserService userSer;

    @RequestMapping(value = "login")
    public ModelAndView login(HttpServletRequest request) {
        System.out.println("LoginController  login +++++");
        String username;
        String password;

        ModelAndView mav = new ModelAndView();

        //1、获取到传入的username 和password
        username = request.getParameter("username");
        password = request.getParameter("password");

        //2、从数据库中获取这个用户的密码
        User user =  userSer.findUserByUsername(username);

        if( null == user){
            System.out.println("无此用户");
            mav.setViewName("redirect:/login.jsp");  //直接用绝对url
        }else {
            if( password.equals( user.getPassword())){
                System.out.println( user.toString());
                mav.setViewName("redirect:/index.jsp");   //直接用绝对url
            }else{
                System.out.println( "密码不正确");
                mav.setViewName("redirect:/login.jsp");
            }

        }
        return mav;
    }

    @RequestMapping(value = "index")
    public ModelAndView doIndex( ) {
        System.out.println("LoginController  doIndex +++++");
        ModelAndView mav = new ModelAndView();

        // 放入jsp路径, 登录后直接显示数据，jsp路径会自动带入
        mav.setViewName("redirect:/index.jsp");
        return mav;
    }



    @RequestMapping("/shiro-login")
    public String login(@RequestParam("username") String username,
                        @RequestParam("password") String password) {

        System.out.println("UserController  here 1111");

        //创建subject实例
        Subject subject = SecurityUtils.getSubject();
        //判断当前用户是否登录
        if (subject.isAuthenticated() == false) {
            //将用户名及密码封装交个UsernamePasswordToken
            UsernamePasswordToken token = new UsernamePasswordToken(username, password);
            try {
                subject.login(token);
            } catch (AuthenticationException e) {
                System.out.println("验证不通过，无法登录！");
                return "error";
            }
        }
        return "success";

    }


    @RequestMapping("/login2") //url
    public String dologin(User user, Model model) {
        String info = loginUser(user);
        if (!"SUCC".equals(info)) {
            model.addAttribute("failMsg", "用户不存在或密码错误！");
            return "/unautorized";
        } else {
            model.addAttribute("successMsg", "登陆成功！");//返回到页面说夹带的参数
            model.addAttribute("name", user.getUserName());
            return "redirect:/index.jsp";//返回的页面
        }
    }


    @RequestMapping("/logout")
    public void logout(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Subject subject = SecurityUtils.getSubject();
        if (subject != null) {
            try {
                subject.logout();
            } catch (Exception ex) {
            }
        }
        response.sendRedirect("/login.jsp");
    }


    private String loginUser(User user) {
        if (isRelogin(user)) return "SUCC"; // 如果已经登陆，无需重新登录

        return shiroLogin(user); // 调用shiro的登陆验证
    }

    private String shiroLogin(User user) {
        // 组装token，包括客户公司名称、简称、客户编号、用户名称；密码
        UsernamePasswordToken token = new UsernamePasswordToken(user.getUserName(), user.getPassword().toCharArray(), null);
        token.setRememberMe(true);

        // shiro登陆验证
        try {
            SecurityUtils.getSubject().login(token);
        } catch (UnknownAccountException ex) {
            return "用户不存在或者密码错误！";
        } catch (IncorrectCredentialsException ex) {
            return "用户不存在或者密码错误！";
        } catch (AuthenticationException ex) {
            return ex.getMessage(); // 自定义报错信息
        } catch (Exception ex) {
            ex.printStackTrace();
            return "内部错误，请重试！";
        }
        return "SUCC";
    }

    private boolean isRelogin(User user) {
        Subject us = SecurityUtils.getSubject();
        if (us.isAuthenticated()) {
            return true; // 参数未改变，无需重新登录，默认为已经登录成功
        }
        return false; // 需要重新登陆
    }


}
