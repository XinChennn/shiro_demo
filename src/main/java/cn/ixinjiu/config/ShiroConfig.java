package cn.ixinjiu.config;

import cn.ixinjiu.controller.LoginController;
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
    // 注入安全管理器
    @Bean
    public ShiroFilterFactoryBean getShiroFilterFactoryBean(@Qualifier("securityManager") DefaultWebSecurityManager defaultWebSecurityManager) {
        ShiroFilterFactoryBean bean = new ShiroFilterFactoryBean();
        // 设置安全管理器
        bean.setSecurityManager(defaultWebSecurityManager);

        // 添加shiro的内置过滤器
        /*
         * anon:  无需认证就可以访问
         * authc: 必须认证了才能让问
         * user:  必须拥有记住我功能才能用
         * perms: 拥有对某个资源的权限才能访问
         * role:  拥有某个角色权限才能访问
         * */
//        Map<String ,String > filterMap = new LinkedHashMap<>();

//        filterMap.put("/user/add", "authc");
//        filterMap.put("/user/update", "authc");
//
//        filterMap.put("/user/*", "authc");
//
//        bean.setFilterChainDefinitionMap(filterMap);

        // 登录路径, 此demo在`LoginController`中配置过了
//        bean.setLoginUrl("/toLogin");

        return bean;
    }

    // DefalutWebSecurityManager  安全管理器
    // @Qualifier注解直接注入了`MyRealm`对象，用法可自行百度
    @Bean(name = "securityManager")
    public DefaultWebSecurityManager getDefaultWebSecurityManager(@Qualifier("myRealm") MyRealm myRealm) {
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        // 关联MyRealm
        securityManager.setRealm(myRealm);
        return securityManager;
    }

    // 创建realm对象，需要自定义类
    @Bean(name = "myRealm")
    public MyRealm myRealm() {
        return new MyRealm();
    }
}
