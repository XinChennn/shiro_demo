package cn.ixinjiu;

import cn.ixinjiu.entity.User;
import cn.ixinjiu.service.UserService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;

@SpringBootTest
class ShiroDemoApplicationTests {
    @Autowired
    private UserService userService;

    @Test
    void contextLoads() {
        // 测试环境是否有问题
        // shiro有问题先不加  -> 接下来进入shiro
        List<User> list = userService.list();
        System.out.println("list = " + list);
    }

}
