package com.ruoyi.web.controller.system;

import java.util.Date;
import java.util.List;
import java.util.Set;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import com.ruoyi.common.constant.Constants;
import com.ruoyi.common.core.domain.AjaxResult;
import com.ruoyi.common.core.domain.entity.SysMenu;
import com.ruoyi.common.core.domain.entity.SysUser;
import com.ruoyi.common.core.domain.model.LoginBody;
import com.ruoyi.common.core.domain.model.LoginUser;
import com.ruoyi.common.core.text.Convert;
import com.ruoyi.common.utils.DateUtils;
import com.ruoyi.common.utils.SecurityUtils;
import com.ruoyi.common.utils.StringUtils;
import com.ruoyi.framework.web.service.SysLoginService;
import com.ruoyi.framework.web.service.SysPermissionService;
import com.ruoyi.framework.web.service.TokenService;
import com.ruoyi.system.service.ISysConfigService;
import com.ruoyi.system.service.ISysMenuService;

/**
 * 登录验证
 * 
 * @author ruoyi
 */
@RestController
public class SysLoginController
{
    @Autowired
    private SysLoginService loginService;

    @Autowired
    private ISysMenuService menuService;

    @Autowired
    private SysPermissionService permissionService;

    @Autowired
    private TokenService tokenService;

    @Autowired
    private ISysConfigService configService;

    /*
    ASK /login 登录流程？
    ANSWER
        1. 先在 CaptchaController 访问 /captchaImage 接口，生成验证码并将验证信息放入 redis 缓存
        2. 用户输入 用户名、密码、验证信息 之后，发送 /login 请求
        3. /login 请求将先经过多个过滤器（包括 ServletFilter、SecurityFilter），但由于此时正处于登录流程，被放行
           a. ServletFilterChain 和 SecurityFilterChain 的嵌套关系算是有些复杂
              所有 SecurityFilter 实际上在FilterChain 中都集中在 DelegateFilter 内部
              在若依中，定义的 RepeatableFilter 等过滤器的优先级低于 SecurityFilter
              所以在 DelegateFilter 执行完毕后，将回到 ServletFilterChain 继续进行原过滤器链
        4. 步入当前 login 方法
        5. 当前方法调用 loginService.login() 方法，进行验证，如果验证成功则生成 token 并返回，否则抛出异常
        6. loginService.login() 方法中，将‘登录流程’拆分为验证码校验、登录前置校验、用户验证、生成token等数个流程
            a. validateCaptcha 主要负责检查验证码是否过期、是否正确，以及刷新 redis 缓存、通过 AsyncManager 进行异步审计日志记录
            b. loginPreCheck 主要负责用户名与密码的合法性校验，不负责主要认证流程，此外还涉及 IP 黑名单校验
            c. 在用户验证流程中，主要通过 Spring Security 的 AuthenticationManager 进行完整验证(验证过程见 SysLoginService 中的记录)
            d. 完成验证后，则通过 tokenService.createToken() 生成token

         若依将整个登录流程进行了颇为细致的拆分
         一开始确实是难以理解将一个领域为何要进行这种程度的拆分
         但现在看来，不管是 CaptchaController、TokenService、SysLoginService、还是AsyncManager
         这种形式确实是足以更好地支撑不同生命周期的流程的复用，同时也能够支撑需求变化下的组件实现替换，而不用大幅重构

         借用 GPT-5.2 的话:
             登录是流程，不是单一领域
             认证、会话、风控、审计均为独立关注点
     */
    /**
     * 登录方法
     * 
     * @param loginBody 登录信息
     * @return 结果
     */
    @PostMapping("/login")
    public AjaxResult login(@RequestBody LoginBody loginBody)
    {
        AjaxResult ajax = AjaxResult.success();
        // 生成令牌
        String token = loginService.login(loginBody.getUsername(), loginBody.getPassword(), loginBody.getCode(),
                loginBody.getUuid());
        ajax.put(Constants.TOKEN, token);
        return ajax;
    }

    /**
     * 获取用户信息
     * 
     * @return 用户信息
     */
    @GetMapping("getInfo")
    public AjaxResult getInfo()
    {
        LoginUser loginUser = SecurityUtils.getLoginUser();
        SysUser user = loginUser.getUser();
        // 角色集合
        Set<String> roles = permissionService.getRolePermission(user);
        // 权限集合
        Set<String> permissions = permissionService.getMenuPermission(user);
        if (!loginUser.getPermissions().equals(permissions))
        {
            loginUser.setPermissions(permissions);
            tokenService.refreshToken(loginUser);
        }
        AjaxResult ajax = AjaxResult.success();
        ajax.put("user", user);
        ajax.put("roles", roles);
        ajax.put("permissions", permissions);
        ajax.put("isDefaultModifyPwd", initPasswordIsModify(user.getPwdUpdateDate()));
        ajax.put("isPasswordExpired", passwordIsExpiration(user.getPwdUpdateDate()));
        return ajax;
    }

    /**
     * 获取路由信息
     * 
     * @return 路由信息
     */
    @GetMapping("getRouters")
    public AjaxResult getRouters()
    {
        Long userId = SecurityUtils.getUserId();
        List<SysMenu> menus = menuService.selectMenuTreeByUserId(userId);
        return AjaxResult.success(menuService.buildMenus(menus));
    }
    
    // 检查初始密码是否提醒修改
    public boolean initPasswordIsModify(Date pwdUpdateDate)
    {
        Integer initPasswordModify = Convert.toInt(configService.selectConfigByKey("sys.account.initPasswordModify"));
        return initPasswordModify != null && initPasswordModify == 1 && pwdUpdateDate == null;
    }

    // 检查密码是否过期
    public boolean passwordIsExpiration(Date pwdUpdateDate)
    {
        Integer passwordValidateDays = Convert.toInt(configService.selectConfigByKey("sys.account.passwordValidateDays"));
        if (passwordValidateDays != null && passwordValidateDays > 0)
        {
            if (StringUtils.isNull(pwdUpdateDate))
            {
                // 如果从未修改过初始密码，直接提醒过期
                return true;
            }
            Date nowDate = DateUtils.getNowDate();
            return DateUtils.differentDaysByMillisecond(nowDate, pwdUpdateDate) > passwordValidateDays;
        }
        return false;
    }
}
