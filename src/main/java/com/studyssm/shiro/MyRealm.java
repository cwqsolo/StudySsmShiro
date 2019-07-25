package com.studyssm.shiro;

import com.studyssm.entity.User;
import com.studyssm.service.UserService;
import com.studyssm.service.impl.UserServiceImpl;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.springframework.beans.factory.annotation.Autowired;

import javax.annotation.Resource;
import java.util.*;


/**
 * Describe:
 *
 * @author cwqsolo
 * @date 2019/07/22
 */
public class MyRealm  extends  AuthorizingRealm{

    @Autowired
    private UserService userService;

    private  User us;


    /**
     * 授权，在配有缓存的情况下，只加载一次。
     * @param principal
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principal) {
        System.out.println("Myrealm  doGetAuthenticationInfo 1++++");
        //当前登录用户，账号
        String username = principal.toString();
        System.out.println("当前登录用户:"+username);
        //获取角色信息
        Set<String> roles = new HashSet<String>();
        roles = userService.findRoles(username);

        if(roles.size()==0){

            System.out.println("当前用户没有角色！");
        }

        SimpleAuthorizationInfo simpleAuthenticationInfo  = null;
        simpleAuthenticationInfo  = new SimpleAuthorizationInfo(roles);
        return simpleAuthenticationInfo ;

    }

    /**
     *  认证登录，查询数据库，如果该用户名正确，得到正确的数据，并返回正确的数据
     * 		AuthenticationInfo的实现类SimpleAuthenticationInfo保存正确的用户信息
     *
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        System.out.println("Myrealm  doGetAuthenticationInfo 2++++");
        //1.将token转换为UsernamePasswordToken
        UsernamePasswordToken userToken = (UsernamePasswordToken)token;

        //2.获取token中的登录账户
        String username = userToken.getUsername();

        //3.查询数据库，是否存在指定的用户名和密码的用户(主键/账户/密码/账户状态/盐)
        us = null;
        us = userService.findUserByUsername(username);

        //4.1 如果没有查询到，抛出异常
        if( us == null ) {
            System.out.println("Myrealm::账户"+username+"不存在！");
            throw new UnknownAccountException("账户"+username+"不存在！");

        }

        //4.2 如果查询到了，封装查询结果，
        Object principal = us.getUserName();
        Object credentials = us.getPassword();
        String realmName = this.getName();

       // String salt = us.getSalt();
        //获取盐，用于对密码在加密算法(MD5)的基础上二次加密ֵ
       //ByteSource byteSalt = ByteSource.Util.bytes(salt);

        SimpleAuthenticationInfo simpleAuthenticationInfo  = new SimpleAuthenticationInfo(principal, credentials, realmName);

        //5. 返回给调用login(token)方法
        return simpleAuthenticationInfo ;
    }

}
