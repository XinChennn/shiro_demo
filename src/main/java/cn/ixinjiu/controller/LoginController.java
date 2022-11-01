package cn.ixinjiu.controller;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.ShiroException;
import org.apache.shiro.authc.*;
import org.apache.shiro.authc.pam.UnsupportedTokenException;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.HostUnauthorizedException;
import org.apache.shiro.authz.UnauthenticatedException;
import org.apache.shiro.authz.UnauthorizedException;
import org.apache.shiro.subject.Subject;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * Created by XinChen on 2022-10-31
 *
 * @Description: TODO 处理登录逻辑
 */
@Controller
public class LoginController {
    // 首页（由于用了thymeleaf模板，返回String就默认等于返回 src/main/resources/templates/xx.html）
    @RequestMapping("")
    public String index() {
        return "login";
    }

    // 处理登录逻辑
    @RequestMapping("/login")
    public String login(String email, String password, Model model) {
        /**
         * shiro的核心组件如果单拿出来说的话会有很多，但有 `3个` 最核心的组件：
         * 1. Subject: 正与系统进行交互的人, 或某一个第三方服务。所有 Subject 实例都被绑定到（且这是必须的）一个SecurityManager 上。
         * 2. SecurityManager：Shiro 架构的心脏, 用来协调内部各安全组件, 管理内部组件实例, 并通过它来提供安全管理的各种服务。
         *    当Shiro 与一个 Subject 进行交互时, 实质上是幕后的 SecurityManager 处理所有繁重的 Subject 安全操作。
         * 3. Realms：本质上是一个特定安全的 DAO。 当配置 Shiro 时, 必须指定至少一个 Realm 用来进行身份验证和/或授权。
         *    Shiro 提供了多种可用的 Realms 来获取安全相关的数据。如关系数据库(JDBC), INI 及属性文件等。 可以定义自己 Realm 实现来代表自定义的数据源。
         * 简单理解：
         *    -> Subject是当前请求登录的用户
         *       SecurityManager是Shiro的核心安全管理器，也可以帮我们处理一些业务比如 注销，跳转到404页面等等
         *       Realm是安全筛选条件，通常情况下由于业务不同，我们大多都采用自定义的方式去定义Realm
         */
        // 获取当前用户
        Subject subject = SecurityUtils.getSubject();
        // 封装用户的登录数据（token在此被封装，在我们自定义的Realm里可以拿到 -> UsernamePasswordToken token = (UsernamePasswordToken) authenticationToken;）
        UsernamePasswordToken token = new UsernamePasswordToken(email, password);
        /**
         * 这里的异常是我们在Realm里抛出的异常，在Controller层捕获，就可以得知用户是为何无法登录了。
         */
        try {
            subject.login(token); // 执行登录方法，如果没有异常说明就ok了

            if (subject.isAuthenticated()) { // 授权
                if (subject.hasRole("admin")) { // 拥有admin权限跳转admin页面
                    return "admin";
                }
            }
            // 否则跳转index页面
            return "index";
        } catch (UnknownAccountException e) { // 用户名不存在
            model.addAttribute("msg", "用户名错误");
            System.out.println("用户名错误");
            return "login";
        } catch (IncorrectCredentialsException e) { // 密码不存在
            // 密码不对的时候跳转login   正确的话跳转 index
            model.addAttribute("msg", "密码错误");
            System.out.println("密码错误");
            return "login";
            /**
             * ---------->  以下列举shiro常用异常
             */
        } catch (UnsupportedTokenException e) { // 身份令牌异常，不支持的身份令牌
            return null;
        } catch (LockedAccountException e) { // 帐号锁定
            return null;
        } catch (DisabledAccountException e) { // 用户禁用
            return null;
        } catch (ExcessiveAttemptsException e) { // 登录重试次数，超限。 只允许在一段时间内允许有一定数量的认证尝试
            return null;
        } catch (ConcurrentAccessException e) { // 一个用户多次登录异常：不允许多次登录，只能登录一次 。即不允许多处登录
            return null;
        } catch (AccountException e) { // 账户异常
            return null;
        } catch (ExpiredCredentialsException e) { // 过期的凭据异常
            return null;
        } catch (CredentialsException e) { // 凭据异常
            return null;
        } catch (AuthenticationException e) { // 凭据异常
            return null;
        } catch (HostUnauthorizedException e) { // 没有访问权限，访问异常
            return null;
        } catch (UnauthorizedException e) { // 没有访问权限，访问异常
            return null;
        } catch (UnauthenticatedException e) { // 授权异常
            return null;
        } catch (AuthorizationException e) { // 授权异常
            return null;
        } catch (ShiroException e) { // shiro全局异常
            return null;
        }

    }
}