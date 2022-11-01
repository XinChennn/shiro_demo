# Shiro-SpringBoot

本demo旨在新手快速了解shiro的认证和授权

**忻辰个人博客**： https://www.ixinjiu.cn

---

# 官网

[官网地址](https://shiro.apache.org/)

# 什么是Shiro？

Shiro是apache旗下一个开源**安全框架**，它将软件系统的安全认证相关的功能抽取出来，实现用户**身份认证，权限授权、加密、会话管理**等功能，组成了一个通用的安全认证框架。

# Shiro 的特点

- Shiro 是一个强大而灵活的开源安全框架，能够非常清晰的处理认证、授权、管理会话以及密码加密。如下是它所具有的特点：
- 易于理解的 Java Security API；
- 简单的身份认证（登录），支持多种数据源（LDAP，JDBC 等）；
- 对角色的简单的签权（访问控制），也支持细粒度的鉴权；
  支持一级缓存，以提升应用程序的性能；
- 内置的基于 POJO 企业会话管理，适用于 Web 以及非 Web 的环境；
- 异构客户端会话访问；
- 非常简单的加密 API；
- 不跟任何的框架或者容器捆绑，可以独立运行。

# Shiro核心架构

![image.png](http://xin-chen123.oss-cn-hangzhou.aliyuncs.com/articles/f7fb82c6ad44ee9682cba5ecff94d31a.png)

# Shiro核心组件

## Subject

Subject主体，外部应用与subject进行交互，subject将用户作为当前操作的主体，这个主体：可以是一个通过浏览器请求的用户，也可能是一个运行的程序。Subject在shiro中是一个接口，接口中定义了很多认证授相关的方法，外部程序通过subject进行认证授，而subject是通过SecurityManager安全管理器进行认证授权

## SecurityManager

SecurityManager权限管理器，它是shiro的核心，负责对所有的subject进行安全管理。通过SecurityManager可以完成subject的认证、授权等，SecurityManager是通过Authenticator进行认证，通过Authorizer进行授权，通过SessionManager进行会话管理等。SecurityManager是一个接口，继承了Authenticator,Authorizer, SessionManager这三个接口

## Authenticator

Authenticator即认证器，对用户登录时进行身份认证

## Authorizer

Authorizer授权器，用户通过认证器认证通过，在访问功能时需要通过授权器判断用户是否有此功能的操作权限。

## Realm（数据库读取+认证功能+授权功能实现）

Realm领域，相当于datasource数据源，securityManager进行安全认证需要通过Realm获取用户权限数据
 
比如：

如果用户身份数据在数据库那么realm就需要从数据库获取用户身份信息。

注意：

不要把realm理解成只是从数据源取数据，在realm中还有**认证授权校验**的相关的代码。

## SessionManager

SessionManager会话管理，shiro框架定义了一套会话管理，它不依赖web容器的session，所以shiro可以使用在非web应用上，也可以将分布式应用的会话集中在一点管理，此特性可使它实现单点登录。

## SessionDAO

SessionDAO即会话dao，是对session会话操作的一套接口
 
比如:
  可以通过jdbc将会话存储到数据库
  也可以把session存储到缓存服务器

## CacheManager

CacheManager缓存管理，将用户权限数据存储在缓存，这样可以提高性能

## Cryptography

Cryptography密码管理，shiro提供了一套加密/解密的组件，方便开发。比如提供常用的散列、加/解密等功能

# Shiro三大核心

1. Subject: 正与系统进行交互的人, 或某一个第三方服务。所有 Subject 实例都被绑定到（且这是必须的）一个SecurityManager 上。

2. SecurityManager：Shiro 架构的心脏, 用来协调内部各安全组件, 管理内部组件实例, 并通过它来提供安全管理的各种服务。
   当Shiro 与一个 Subject 进行交互时, 实质上是幕后的 SecurityManager 处理所有繁重的 Subject 安全操作。

3. Realms：本质上是一个特定安全的 DAO。 当配置 Shiro 时, 必须指定至少一个 Realm 用来进行身份验证和/或授权。
   Shiro 提供了多种可用的 Realms 来获取安全相关的数据。如关系数据库(JDBC), INI 及属性文件等。 可以定义自己 Realm 实现来代表自定义的数据源。

**简单理解：**

> Subject是当前请求登录的用户
>
> SecurityManager是Shiro的核心安全管理器，也可以帮我们处理一些业务比如 注销，跳转到404页面等等
>
> Realm是安全筛选条件，通常情况下由于业务不同，我们大多都采用自定义的方式去定义Realm

**官网说十分钟就学会了。**

# 案例源码

[Gitee](案例源码) | [GitHub](https://github.com/XinChennn/shiro_demo)

# QuickStart

## 数据表

准备一张非常简单的user表

| id   | email         | password |
| ---- | ------------- | -------- |
| 1    | test@test.com | 123      |
| 4    | aaa@a.com     | 789      |
| 5    | 123@123.com   | 123456   |
| 6    | 789@789.com   | 123456   |

其对应的数据库 `Schema` 脚本如下：

```sql
DROP TABLE IF EXISTS `user`;
CREATE TABLE `user`  (
  `id` int NOT NULL AUTO_INCREMENT,
  `email` varchar(30) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `password` varchar(40) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 7 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_bin COMMENT = '用户表' ROW_FORMAT = Dynamic;

INSERT INTO `user` VALUES (1, 'test@test.com', '123');
INSERT INTO `user` VALUES (4, 'aaa@a.com', '789');
INSERT INTO `user` VALUES (5, '123@123.com', '123456');
INSERT INTO `user` VALUES (6, '789@789.com', '123456');
```

**创建springboot工程`shiro-demo`**

## 引入依赖

```xml
<dependencies>
    <!-- web -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <!-- mp -->
    <dependency>
        <groupId>com.baomidou</groupId>
        <artifactId>mybatis-plus-boot-starter</artifactId>
        <version>3.5.2</version>
    </dependency>
    <!-- shiro -->
    <dependency>
        <groupId>org.apache.shiro</groupId>
        <artifactId>shiro-spring-boot-starter</artifactId>
        <version>1.5.3</version>
    </dependency>
    <!-- thymeleaf -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-thymeleaf</artifactId>
    </dependency>
    <!-- mysql -->
    <dependency>
        <groupId>com.mysql</groupId>
        <artifactId>mysql-connector-j</artifactId>
        <scope>runtime</scope>
    </dependency>
    <!-- lombok -->
    <dependency>
        <groupId>org.projectlombok</groupId>
        <artifactId>lombok</artifactId>
        <optional>true</optional>
    </dependency>
    <!-- test -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-test</artifactId>
        <scope>test</scope>
    </dependency>
</dependencies>
```

## yml配置文件

 ```yaml
server:
  port: 8081
spring:
  datasource:
    password: 123456
    username: root
    driver-class-name: com.mysql.cj.jdbc.Driver
    url: jdbc:mysql://localhost:3306/ginhello
 ```

## config

**MyRealm.java**

```java
package cn.ixinjiu.config;

import cn.ixinjiu.entity.User;
import cn.ixinjiu.service.UserService;
import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * Created by XinChen on 2022-10-31
 *
 * @Description: TODO 自定义realm
 */
public class MyRealm extends AuthorizingRealm {
    @Autowired
    private UserService userService;

    // 认证
    // 该方法可以判断用户是否可以成功认证，可抛出多种异常给controller，来判断用户的登录状态
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        System.out.println(" -------------------->  执行认证  <------------------ ");
        // 这个token是Controller层封装的token （ UsernamePasswordToken token = new UsernamePasswordToken(email, password); ）
        UsernamePasswordToken token = (UsernamePasswordToken) authenticationToken;
        // 获取到用户名
        String username = token.getUsername();
        // 打印一下看是否是用户名
        System.out.println("username = " + username);

        // 根据用户名查询用户
        LambdaQueryWrapper<User> queryWrapper = new LambdaQueryWrapper<>();
        queryWrapper.eq(User::getEmail, username);
        User user = userService.getOne(queryWrapper);
        System.out.println("user =------------> " + user);
        if (user == null) { // 如果没有查到用户，就返回null，Controller层捕获 UnknownAccountException 异常
            return null;
        } else { // 根据用户名查到了用户，比对密码是否正确

            // 三个参数：username（查询到的用户的用户名）, password（查询到的用户的密码）, realmName（自定义的Realm类名）
            // 这个方法是在底层做判断，也就是通过用户名查到了user, 比对密码是否正确（user.getPassword() ?= token.getPassword()）
            return new SimpleAuthenticationInfo(user.getEmail(), user.getPassword(), this.getName());

//            return new SimpleAuthenticationInfo(user.getEmail(), user.getPassword(), MyRealm.class.getName());
        }
    }

    // 授权
    // 该方法用来判断是否有权限执行操作
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        System.out.println(" -------------------->  执行授权  <------------------ ");
        return null;
    }
}

```

**ShiroConfig.java**

```java
package cn.ixinjiu.config;

import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Created by XinChen on 2022-10-31
 *
 * @Description: TODO shiro的核心配置
 */
@Configuration
// 从下往上写   向config中配置核心组件
public class ShiroConfig {
    // 过滤器
    @Bean
    public ShiroFilterFactoryBean getShiroFilterFactoryBean(@Qualifier("securityManager") DefaultWebSecurityManager defaultWebSecurityManager){
        ShiroFilterFactoryBean bean = new ShiroFilterFactoryBean();
        // 设置安全管理器
        bean.setSecurityManager(defaultWebSecurityManager);

        //添加shiro的内置过滤器
        /*
         * anon:无需认证就可以访问
         * authc:必须认证了才能让问
         * user: 必须拥有记住我功能才能用
         * perms:拥有对某个资源的权限才能访问、
         * role:拥有某个角色权限才能访问
         * */
//
//        Map<String ,String > filterMap = new LinkedHashMap<>();
//        filterMap.put("/user/add","authc");
//        filterMap.put("/user/update","authc");

//        filterMap.put("/user/*","authc");

//        bean.setFilterChainDefinitionMap(filterMap);
        // 登录路径
        bean.setLoginUrl("/toLogin");

        return bean;
    }

    // DefalutWebSecurityManager  安全管理器
    @Bean(name = "securityManager")
    public DefaultWebSecurityManager getDefaultWebSecurityManager(@Qualifier("myRealm") MyRealm myRealm){
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        // 关联MyRealm
        securityManager.setRealm(myRealm);
        return securityManager;
    }

    // 创建realm对象，需要自定义类
    @Bean(name = "myRealm")
    public MyRealm myRealm(){
        return new MyRealm();
    }
}
```

## entity

**User.java**

```java
package cn.ixinjiu.entity;

import lombok.Data;

/**
 * Created by XinChen on 2022-10-31
 *
 * @Description: TODO
 */
@Data
public class User {
    private int id;
    private String email;
    private String password;
}
```



## mapper

**UserMapper.java**

```java
package cn.ixinjiu.mapper;

import cn.ixinjiu.entity.User;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface UserMapper extends BaseMapper<User> {
}
```

## service

**UserService.java**

```java
package cn.ixinjiu.service;

import cn.ixinjiu.entity.User;
import com.baomidou.mybatisplus.extension.service.IService;

public interface UserService extends IService<User> {
}
```

### service.impl

```java
package cn.ixinjiu.service.impl;

import cn.ixinjiu.entity.User;
import cn.ixinjiu.mapper.UserMapper;
import cn.ixinjiu.service.UserService;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.springframework.stereotype.Service;

/**
 * Created by XinChen on 2022-10-31
 *
 * @Description: TODO
 */
@Service
public class UserServiceImpl extends ServiceImpl<UserMapper, User> implements UserService {
}
```

## controller

**LoginController.java**

```java
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
            return "index";
        } catch (UnknownAccountException e) { // 用户名不存在
            model.addAttribute("msg", "用户名错误");
            System.out.println("用户名错误");
            return "login";
        } catch (IncorrectCredentialsException e) { // 密码不存在
            // 密码不对的时候跳转login   正确的话跳转 index
            // 就这样   学完啦！！！！！
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
```

## 页面

在`src/main/resources/templates`目录下创建`index.html（跳转成功的页面）`, `login.html（登录页面）`

**index.html**

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>index</title>
</head>
<body>
<h1>INDEX</h1>
</body>
</html>
```

**login.html**

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>login</title>
</head>
<body>
<h1>LOGIN</h1>
<form action="/login">
    <table>
        <tr>
            <td>email</td>
            <td><input type="text" name="email"></td>
        </tr>
        <tr>
            <td>password</td>
            <td><input type="password" name="password"></td>
        </tr>
        <tr>
            <td>
                <button type="submit">submit</button>
            </td>
        </tr>
    </table>
</form>
</body>
</html>
```

运行测试，只有完全符合数据库的email和password才能跳转index页面。  至此完成了**shiro的认证**。

**授权**的原理非常简单，在realm里实现 **doGetAuthorizationInfo()** 即可。

权限必然配置在数据库里，我们在代码中对权限进行判断。

# 授权

## 数据表

> 新增`role`表和`user_role`表

`role`表

| id   | role_name |
| ---- | --------- |
| 1    | admin     |
| 2    | user      |
| 3    | test      |

`Schema` 脚本

```sql
DROP TABLE IF EXISTS `role`;
CREATE TABLE `role`  (
  `id` int NOT NULL AUTO_INCREMENT COMMENT '权限id',
  `role_name` varchar(30) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL DEFAULT NULL COMMENT '权限名',
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 4 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_bin ROW_FORMAT = Dynamic;

INSERT INTO `role` VALUES (1, 'admin');
INSERT INTO `role` VALUES (2, 'user');
INSERT INTO `role` VALUES (3, 'test');
```

`user_role`表

| id   | role_id | user_id |
| ---- | ------- | ------- |
| 1    | 3       | 1       |
| 2    | 1       | 5       |
| 3    | 2       | 4       |
| 4    | 2       | 6       |

`Schema` 脚本

```sql
DROP TABLE IF EXISTS `user_role`;
CREATE TABLE `user_role`  (
  `id` int NOT NULL AUTO_INCREMENT COMMENT '用户-权限表id',
  `role_id` int NULL DEFAULT NULL COMMENT '权限id',
  `user_id` int NULL DEFAULT NULL COMMENT '用户id',
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 5 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_bin ROW_FORMAT = Dynamic;

INSERT INTO `user_role` VALUES (1, 3, 1);
INSERT INTO `user_role` VALUES (2, 1, 5);
INSERT INTO `user_role` VALUES (3, 2, 4);
INSERT INTO `user_role` VALUES (4, 2, 6);
```

## config

> 修改MyRealm.java类

```java
package cn.ixinjiu.config;

import cn.ixinjiu.entity.User;
import cn.ixinjiu.entity.UserRole;
import cn.ixinjiu.service.UserRoleService;
import cn.ixinjiu.service.UserService;
import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * Created by XinChen on 2022-10-31
 *
 * @Description: TODO 自定义realm
 */
public class MyRealm extends AuthorizingRealm {
    @Autowired
    private UserService userService;
    @Autowired
    private UserRoleService userRoleService;

    // 认证
    // 该方法可以判断用户是否可以成功认证，可抛出多种异常给controller，来判断用户的登录状态
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        System.out.println(" -------------------->  执行认证  <--------------------- ");
        // 这个token是Controller层封装的token （ UsernamePasswordToken token = new UsernamePasswordToken(email, password); ）
        UsernamePasswordToken token = (UsernamePasswordToken) authenticationToken;
        // 获取到用户名
        String username = token.getUsername();
        // 打印一下看是否是用户名
        System.out.println("username = " + username);

        // 根据用户名查询用户
        LambdaQueryWrapper<User> queryWrapper = new LambdaQueryWrapper<>();
        queryWrapper.eq(User::getEmail, username);
        User user = userService.getOne(queryWrapper);
        System.out.println("user =------------> " + user);
        if (user == null) { // 如果没有查到用户，就返回null，Controller层捕获 UnknownAccountException 异常
            return null;
        } else { // 根据用户名查到了用户，比对密码是否正确

            // 三个参数：username（查询到的用户的用户名）, password（查询到的用户的密码）, realmName（自定义的Realm类名）
            // 这个方法是在底层做判断，也就是通过用户名查到了user, 比对密码是否正确（user.getPassword() ?= token.getPassword()）
            return new SimpleAuthenticationInfo(user.getEmail(), user.getPassword(), this.getName());

//            return new SimpleAuthenticationInfo(user.getEmail(), user.getPassword(), MyRealm.class.getName());
        }
    }

    // 授权
    // 该方法用来判断是否有权限执行操作
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        System.out.println(" -------------------->  执行授权  <--------------------- ");

        String primaryPrincipal = (String) principalCollection.getPrimaryPrincipal();
        System.out.println("身份信息 = " + primaryPrincipal);
        // 根据用户名获取当前用户的权限信息
        SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo();
        // 根据用户名查询到用户
        User user = userService.getOne(new LambdaQueryWrapper<User>().eq(User::getEmail, primaryPrincipal));
        // 根据用户的id获取权限id
        UserRole userRole = userRoleService.getOne(new LambdaQueryWrapper<UserRole>().eq(UserRole::getUserId, user.getId()));
        // 将数据库中查询角色信息赋值给权限对象
        if (userRole.getRoleId() == 1) {
            simpleAuthorizationInfo.addRole("admin");
        } else if (userRole.getRoleId() == 2) {
            simpleAuthorizationInfo.addRole("user");
        } else {
            simpleAuthorizationInfo.addRole("test");
        }
        // 返回权限信息对象
        return simpleAuthorizationInfo;
    }
}
```

## entity

> 新增UserRole.java

```java
package cn.ixinjiu.entity;

import lombok.Data;

/**
 * Created by XinChen on 2022-11-01
 *
 * @Description: TODO
 */
@Data
public class UserRole {
    private int id;
    private int roleId;
    private int userId;
}
```

## mapper

> 新增UserRoleMapper.java

```java
package cn.ixinjiu.mapper;

import cn.ixinjiu.entity.UserRole;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface UserRoleMapper extends BaseMapper<UserRole> {
}
```

## service

> 新增UserService.java

```java
package cn.ixinjiu.service;

import cn.ixinjiu.entity.UserRole;
import com.baomidou.mybatisplus.extension.service.IService;

public interface UserRoleService extends IService<UserRole> {
}
```

### service.impl

> 新增UserRoleServiceImpl.java

```java
package cn.ixinjiu.service.impl;

import cn.ixinjiu.entity.UserRole;
import cn.ixinjiu.mapper.UserRoleMapper;
import cn.ixinjiu.service.UserRoleService;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.springframework.stereotype.Service;

/**
 * Created by XinChen on 2022-11-01
 *
 * @Description: TODO
 */
@Service
public class UserRoleServiceImpl extends ServiceImpl<UserRoleMapper, UserRole> implements UserRoleService {
}
```

## controller

> 修改LoginController.java类

```java
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
```

## 页面

> 新增admin.html

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>admin</title>
</head>
<body>
<h1>ADMIN页面，拥有管理员权限才能访问</h1>
</body>
</html>
```

运行测试，只有 email=123@123.com 的账户才可以进入admin页面，其余用户只可以进入index页面。

这就是权限管理在发挥作用啦~