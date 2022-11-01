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
