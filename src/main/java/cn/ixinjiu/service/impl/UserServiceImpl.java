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
