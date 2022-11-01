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
