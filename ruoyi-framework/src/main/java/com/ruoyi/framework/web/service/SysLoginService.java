package com.ruoyi.framework.web.service;

import jakarta.annotation.Resource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import com.ruoyi.common.constant.CacheConstants;
import com.ruoyi.common.constant.Constants;
import com.ruoyi.common.constant.UserConstants;
import com.ruoyi.common.core.domain.model.LoginUser;
import com.ruoyi.common.core.redis.RedisCache;
import com.ruoyi.common.exception.ServiceException;
import com.ruoyi.common.exception.user.BlackListException;
import com.ruoyi.common.exception.user.CaptchaException;
import com.ruoyi.common.exception.user.CaptchaExpireException;
import com.ruoyi.common.exception.user.UserNotExistsException;
import com.ruoyi.common.exception.user.UserPasswordNotMatchException;
import com.ruoyi.common.utils.DateUtils;
import com.ruoyi.common.utils.MessageUtils;
import com.ruoyi.common.utils.StringUtils;
import com.ruoyi.common.utils.ip.IpUtils;
import com.ruoyi.framework.manager.AsyncManager;
import com.ruoyi.framework.manager.factory.AsyncFactory;
import com.ruoyi.framework.security.context.AuthenticationContextHolder;
import com.ruoyi.system.service.ISysConfigService;
import com.ruoyi.system.service.ISysUserService;

/**
 * 登录校验方法
 *
 * @author ruoyi
 */
@Component
public class SysLoginService
{
    @Autowired
    private TokenService tokenService;

    @Resource
    private AuthenticationManager authenticationManager;

    @Autowired
    private RedisCache redisCache;

    @Autowired
    private ISysUserService userService;

    @Autowired
    private ISysConfigService configService;

    /**
     * 登录验证
     *
     * @param username 用户名
     * @param password 密码
     * @param code 验证码
     * @param uuid 唯一标识
     * @return 结果
     */
    public String login(String username, String password, String code, String uuid)
    {
        // 验证码校验
        validateCaptcha(username, code, uuid);
        // 登录前置校验
        loginPreCheck(username, password);
        // 用户验证
        Authentication authentication = null;
        try
        {
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password);
            AuthenticationContextHolder.setContext(authenticationToken);
            // 该方法会去调用UserDetailsServiceImpl.loadUserByUsername
            /*
            ASK AuthenticationManager 认证流程？
            ANSWER
                借助调试可以看到，authenticationManager.getClass() 看到的类型实际为 ProviderManager
                而在 ProviderManager 中可以看到存在一个 DaoAuthenticationProvider
                翻阅源码(至 AbstractDaoAuthenticationConfigurer 处)可以得知，DaoAuthenticationProvider 为 UserDetails 方式下的默认 Provider
                Provider 在构造时通过构造方法注入 UserDetailsService
                DaoAuthenticationProvider 继承自 AbstractUserDetailsAuthenticationProvider，实现模板方法
                父类提供完整的 authenticate 流程，返回 Authentication
             */
            authentication = authenticationManager.authenticate(authenticationToken);
        }
        catch (Exception e)
        {
            if (e instanceof BadCredentialsException)
            {
                AsyncManager.me().execute(AsyncFactory.recordLogininfor(username, Constants.LOGIN_FAIL, MessageUtils.message("user.password.not.match")));
                throw new UserPasswordNotMatchException();
            }
            else
            {
                AsyncManager.me().execute(AsyncFactory.recordLogininfor(username, Constants.LOGIN_FAIL, e.getMessage()));
                throw new ServiceException(e.getMessage());
            }
        }
        finally
        {
            AuthenticationContextHolder.clearContext();
        }
        AsyncManager.me().execute(AsyncFactory.recordLogininfor(username, Constants.LOGIN_SUCCESS, MessageUtils.message("user.login.success")));
        LoginUser loginUser  = (LoginUser) authentication.getPrincipal();
        recordLoginInfo(loginUser.getUserId());
        // 生成token
        /*
        ASK 为什么将 Token 独立为另一个 Service ?
        ANSWER
            若依将‘登录’这一功能进行了拆分
            由多个独立的领域(Token、Captcha、Async异步审计日志、AuthenticationManager)组成
            Token 的生命周期，远大于“登录”这一个动作。
            TokenService 要处理的事情包括：生成、刷新、校验、续期、失效、踢人
            如果它写死在 login 里：
                无法支持刷新 token
                无法支持多端登录
                无法支持强制下线
         */
        return tokenService.createToken(loginUser);
    }

    /**
     * 校验验证码
     *
     * @param username 用户名
     * @param code 验证码
     * @param uuid 唯一标识
     * @return 结果
     */
    public void validateCaptcha(String username, String code, String uuid)
    {
        boolean captchaEnabled = configService.selectCaptchaEnabled();
        if (captchaEnabled)
        {
            String verifyKey = CacheConstants.CAPTCHA_CODE_KEY + StringUtils.nvl(uuid, "");
            /*
            ASK redis 中的验证码在哪里被放入？
            ANSWER
                起初以为这些和 Spring Security 的认证体系相关
                但后来发现实际上存在一个 CaptchaController
                在那里生成验证码时，captcha 就已经被放到 redis 缓存中
                这是登录前的人机校验/风控逻辑，与 AuthenticationManager 无关
             */
            String captcha = redisCache.getCacheObject(verifyKey);
            if (captcha == null)
            {
                /*
                ASK 异步任务机制与细节
                ANSWER
                    若依中，该异步体系主要针对异步日志的记录使用
                    AsyncManager
                        使用单例模式，类型加载时即进行实例化，通过`me()`方法获取实例;
                        借助 SpringUtils 获取 ScheduledExecutorService, 用于后续执行异步任务;
                        内部设有 10ms 延迟，可避免任务立即被调度从而与当前请求线程争夺 CPU, 高负载时可推迟日志任务带来的负载进行削峰
                    AsyncFactory
                        用于生产异步任务（主要是异步日志）;
                        当前返回值为 TimerTask，但现在看来似乎是没有必要的
                        除了语义那一层存在关联外，TimerTask 中除了继承自 Runnable 接口实现的 run 方法外，剩余的字段似乎都没有使用
                        内部调用的 ServletUtils 封装了 RequestContextHolder 来获取必要的请求信息
                        后者又用到了 ThreadLocal, 所以‘通过 ServletUtils 获取请求信息’只在请求线程可用

                    本来对 AsyncFactory 直接通过 SpringUtils 拿取 ISysLogininforService 记录日志存在‘越界’相关的疑问
                    但考虑到这部分异步日志处理，也的确要用到 ISysLogininforService 相关的逻辑
                    如果独立为类似 AsyncLogService 虽说看起来似乎免除了这种‘越界’，但实际上却多了一个不存在、难以解释的业务领域
                    而引入其他方式（如事件发布等）也确实抽象过多。这样看它的实现应该算是一次工程妥协吧。
                 */
                AsyncManager.me().execute(AsyncFactory.recordLogininfor(username, Constants.LOGIN_FAIL, MessageUtils.message("user.jcaptcha.expire")));
                /*
                ASK 异常处理体系
                ANSWER
                    若依的异常体系确实要丰富一些
                    以此处的 CaptchaExpireException 为例
                    整个继承链为: CaptchaExpireException  -> UserException -> BaseException -> RuntimeException
                    异常构造过程中，会将对应的异常码逐级向上传递，最终存储在 BaseException 中定义的 code 属性中
                    最终的 BaseException 异常又重写了 getMessage 方法，方法内部调用 MessageUtils 获取该异常码对应的 i18n 错误信息
                    而 GlobalExceptionHandler 中定义的全局异常处理逻辑，则只负责对消息进行必要的清洗并通过 log.error() 打印异常信息并记录

                    对于 MessageUtils 中的国际化处理，该工具类内部的注释提到会提到委托给 Spring MessageSource
                    MessageSource 作为 Spring 提供的‘国际化消息查找抽象接口’，可根据 Locale 扫描对应的 messages.properties 并获取文本

                    这种方式确实是比‘将异常信息写死在异常抛出位置’要灵活、统一多了
                 */
                throw new CaptchaExpireException();
            }
            redisCache.deleteObject(verifyKey);
            if (!code.equalsIgnoreCase(captcha))
            {
                AsyncManager.me().execute(AsyncFactory.recordLogininfor(username, Constants.LOGIN_FAIL, MessageUtils.message("user.jcaptcha.error")));
                throw new CaptchaException();
            }
        }
    }

    /**
     * 登录前置校验
     * @param username 用户名
     * @param password 用户密码
     */
    public void loginPreCheck(String username, String password)
    {
        // 用户名或密码为空 错误
        if (StringUtils.isEmpty(username) || StringUtils.isEmpty(password))
        {
            AsyncManager.me().execute(AsyncFactory.recordLogininfor(username, Constants.LOGIN_FAIL, MessageUtils.message("not.null")));
            throw new UserNotExistsException();
        }
        // 密码如果不在指定范围内 错误
        if (password.length() < UserConstants.PASSWORD_MIN_LENGTH
                || password.length() > UserConstants.PASSWORD_MAX_LENGTH)
        {
            AsyncManager.me().execute(AsyncFactory.recordLogininfor(username, Constants.LOGIN_FAIL, MessageUtils.message("user.password.not.match")));
            throw new UserPasswordNotMatchException();
        }
        // 用户名不在指定范围内 错误
        if (username.length() < UserConstants.USERNAME_MIN_LENGTH
                || username.length() > UserConstants.USERNAME_MAX_LENGTH)
        {
            AsyncManager.me().execute(AsyncFactory.recordLogininfor(username, Constants.LOGIN_FAIL, MessageUtils.message("user.password.not.match")));
            throw new UserPasswordNotMatchException();
        }
        // IP黑名单校验
        String blackStr = configService.selectConfigByKey("sys.login.blackIPList");
        //TODO IP如何获取？
        if (IpUtils.isMatchedIp(blackStr, IpUtils.getIpAddr()))
        {
            AsyncManager.me().execute(AsyncFactory.recordLogininfor(username, Constants.LOGIN_FAIL, MessageUtils.message("login.blocked")));
            throw new BlackListException();
        }
    }

    /**
     * 记录登录信息
     *
     * @param userId 用户ID
     */
    public void recordLoginInfo(Long userId)
    {
        userService.updateLoginInfo(userId, IpUtils.getIpAddr(), DateUtils.getNowDate());
    }
}
