#   shiro+cas微服务化笔记
##   1.Spring Boot 配置

有如下两个配置文件：ShiroBaseConfig.java   

```   java

import lombok.extern.log4j.Log4j;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.cache.MemoryConstrainedCacheManager;
import org.apache.shiro.cas.CasFilter;
import org.apache.shiro.codec.Base64;
import org.apache.shiro.session.mgt.eis.MemorySessionDAO;
import org.apache.shiro.web.mgt.CookieRememberMeManager;
import org.apache.shiro.web.servlet.SimpleCookie;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * <p>
 * Description: shiro权限管理模块conf
 *
 * @author Dean.Hwang
 * @date 17/5/18
 */
@Configuration
@Log4j
public class ShiroBaseConfiguration {
    @Value("${cas.server.url.prefix}")
    private String casPrefix;
    @Value("${cas.service}")
    private String casService;
    
    /**
     * 会话Cookie模板
     *
     * @return
     */
    @Bean
    public SimpleCookie sessionIdCookie() {
        SimpleCookie simpleCookie = new SimpleCookie("sid");
        simpleCookie.setHttpOnly(true);
        simpleCookie.setMaxAge(1800000);
        return simpleCookie;
    }

    /**
     * 会话Cookie模板
     *
     * @return
     */
    @Bean
    public SimpleCookie rememberCookie() {
        SimpleCookie simpleCookie = new SimpleCookie("rememberMe");
        simpleCookie.setHttpOnly(true);
        simpleCookie.setMaxAge(2592000);//30天
        return simpleCookie;
    }

    /**
     * rememberMe 管理器
     *
     * @return
     */
    @Bean
    public CookieRememberMeManager rememberMeManager(SimpleCookie rememberCookie) {
        CookieRememberMeManager cookieRememberMeManager = new CookieRememberMeManager();
        cookieRememberMeManager.setCipherKey(Base64.decode(""));// rememberMe cookie加密的密钥 建议每个项目都不一样 默认AES算法 密钥长度（128 256 512 位）
        cookieRememberMeManager.setCookie(rememberCookie);
        return cookieRememberMeManager;
    }

    /**
     * 会话DAO
     *
     * @return
     */
    @Bean
    public MemorySessionDAO sessionDAO() {
        return new MemorySessionDAO();
    }


    @Bean
    public CacheManager shiroCacheManager() {
        return new MemoryConstrainedCacheManager();
    }

    @Bean
    public KryCasRealm casRealm(CacheManager shiroCacheManager) {
        return new KryCasRealm(casPrefix, casService, shiroCacheManager);
    }

    @Bean
    public CasFilter casFilter() {
        CasFilter casFilter = new CasFilter();
        casFilter.setEnabled(true);
        casFilter.setName("casFilter");
        casFilter.setFailureUrl("/authority/casFailure");
        return casFilter;
    }


}


```   

下面ShiroManagerConfiguration.java 文件   

```java

import com.keruyun.portal.portalbiz.sso.KryCasRealm;
import com.keruyun.portal.portalbiz.sso.filter.PortalUserFilter;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.cas.CasFilter;
import org.apache.shiro.cas.CasSubjectFactory;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.filter.authc.LogoutFilter;
import org.apache.shiro.web.mgt.CookieRememberMeManager;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.session.mgt.ServletContainerSessionManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.config.MethodInvokingFactoryBean;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.servlet.Filter;
import java.util.HashMap;
import java.util.Map;

/**
 * <p>
 * Description: com.keruyun.portal.portalbiz.conf.shiro
 * </p>
 * <p>
 * Copyright: Copyright (c) 2015
 * </p>
 * <p>
 * Company: 客如云
 * </p>
 *
 * @author Dean.Hwang
 * @date 17/5/18
 */
@Configuration
@AutoConfigureAfter(
        {ShiroBaseConfiguration.class}
)
public class ShiroManagerConfiguration {
    @Autowired
    private KryCasRealm kryCasRealm;
    @Autowired
    private CacheManager shiroCacheManager;
    @Autowired
    private CookieRememberMeManager rememberMeManager;
    @Value("${cas.server.login.url}")
    private String loginUrl;
    @Value("${cas.client.url.prefix}")
    private String urlPrefix;
    @Autowired
    private CasFilter casFilter;
    @Value("${cas.server.logout.url}")
    private String logoutUrl;
    @Value("${cas.client.index.url}")
    private String indexUrl;

    @Bean
    public DefaultWebSecurityManager securityManager() {
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        securityManager.setRealm(kryCasRealm);
        securityManager.setSessionManager(new ServletContainerSessionManager());
        securityManager.setCacheManager(shiroCacheManager);
        securityManager.setRememberMeManager(rememberMeManager);
        securityManager.setSubjectFactory(new CasSubjectFactory());
        return securityManager;
    }

    /**
     * 相当于调用SecurityUtils.setSecurityManager(securityManager)
     *
     * @param securityManager
     * @return
     */
    @Bean
    public MethodInvokingFactoryBean methodInvokingFactoryBean(DefaultWebSecurityManager securityManager) {
        MethodInvokingFactoryBean bean = new MethodInvokingFactoryBean();
        bean.setStaticMethod("org.apache.shiro.SecurityUtils.setSecurityManager");
        bean.setArguments(new Object[]{securityManager});
        return bean;
    }

    @Bean
    public ShiroFilterFactoryBean shiroFilter(DefaultWebSecurityManager securityManager) {
         ShiroFilterFactoryBean factoryBean = new ShiroFilterFactoryBean();
        factoryBean.setSecurityManager(securityManager);
        factoryBean.setLoginUrl(loginUrl + serviceStr + urlPrefix + "/cas");
        factoryBean.setSuccessUrl("../mind/index.do");
        factoryBean.setUnauthorizedUrl("/unauthorized.jsp");
        Map<String, Filter> filterMap = new HashMap<>();
        filterMap.put("cas", casFilter);
        filterMap.put("user", portalUserFilter);
        //只能在这里初始化LogoutFilter，不然会被spring boot注册到/*
        PortalLogoutFilter logoutFilter = new PortalLogoutFilter();
        logoutFilter.setRedirectUrl(logoutUrl + serviceStr + indexUrl);
        filterMap.put("logout", logoutFilter);
        factoryBean.setFilters(filterMap);
        Map<String, String> filters = new HashMap<>();
        filters.put("/casFailure.jsp", "anon");
        filters.put("/js/**", "anon");
        filters.put("/themes/**", "anon");
        filters.put("/3rdOauth/**", "anon");
        filters.put("/cas", "cas");
        filters.put("/logout", "logout");
        filters.put("/**", "user");
        factoryBean.setFilterChainDefinitionMap(filters);
        return factoryBean;    }
}   
```
##   2.UserFilter的改造
###   2.1改造的原因：
  因为，我们现在新的服务器架构是前后端完全分离的。但是，shiro是不支持完全的前后端分离。所以导致了单点登录完成以后会跳转至接口，而不是目标页面。同时，由于历史原因，我们的cas验证服务器与业务服务器不是同一个域。如果，需要在服务器端进行重定向就必须要通过跨域，考虑到跨域会有风险。所以，我也将sso服务器登录重定向进行了重构。做成了返回json，前端在接收到json自己进行登录页跳转。
  具体的实现代码如下:
  
```java
protected void saveRequestAndRedirectToLogin(ServletRequest request, ServletResponse response) throws IOException {
        Session session = SecurityUtils.getSubject().getSession();
        if (session != null) {
            SavedRequest savedRequest = new PortalSavedRequest(WebUtils.toHttp(request));//重写的SavedRequest，具体处理由不同的业务需求自定
            session.setAttribute(SAVED_REQUEST_KEY, savedRequest);

        }
        PrintWriter out = null;
        try {
            ResultVO<Object> vo = ResultVO.isRedirect();
            RedirectInfo info = new RedirectInfo(loginRedirectUrl);
            vo.setData(info);
            response.setCharacterEncoding("UTF-8");
            response.setContentType("application/json; charset=utf-8");
            out = response.getWriter();
            out.write(JsonMapper.nonDefaultMapper().toJson(vo));
        } catch (IOException e) {
            log.error("登录重定向失败(Login Redirect Failed)", e);
        } finally {
            if (out != null) {
                out.close();
            }
        }
    }
```

此方法是将Cas中的Userfilter进行了重写，并且在配置时使用重写的类对原有的UserFilter进行了覆盖。

#3.登录成功后的重定向:
由于在sso验证服务器登录成功以后会重定向到本地业务服务器上。本地业务服务器验证登录成功以后会默认重定向至配置的SuccessUrl。这样并不能将页面跳转回用户的原来请求的页面。所以我重写了CasFilter中的issueSuccessRedirect达到这个目的
```java
/**
 * <p>
 * Description: com.keruyun.portal.portalbiz.sso.filter
 * </p>
 * <p>
 * Copyright: Copyright (c) 2015
 * </p>
 * <p>
 * Company: 客如云
 * </p>
 *
 * @author Dean.Hwang
 * @date 17/7/17
 */
public class PortalCasFilter extends CasFilter {

    @Override
    protected void issueSuccessRedirect(ServletRequest request, ServletResponse response) throws Exception {
        String successUrl = ((ShiroHttpServletRequest) request).getHeader("page-url");//前端页面在请求的时候在header中带上请求这个接口的url。这样便将登录成功后需要跳转的地址绑定到了对应的Subject对象中。以便于在登录以后跳转到这个页面
        if (StringUtil.isBlank(successUrl)) {
            WebUtils.redirectToSavedRequest(request, response, getSuccessUrl());
        } else {
            WebUtils.redirectToSavedRequest(request, response, successUrl);
        }
    }
}
```
#4.用户安全的退出
后期发现直接依靠原有的logout会发生session未注销的情况。所以重写了LogoutFilter。登出的时候直接调用配置的URL即可

```java
/**
 * <p>
 * Description: com.keruyun.portal.portalbiz.sso.filter
 * </p>
 * <p>
 * Copyright: Copyright (c) 2015
 * </p>
 * <p>
 * Company: 客如云
 * </p>
 *
 * @author Dean.Hwang
 * @date 17/7/17
 */
public class PortalLogoutFilter extends AdviceFilter {

    private static final Logger log = LoggerFactory.getLogger(LogoutFilter.class);

    public static final String DEFAULT_REDIRECT_URL = "/";

    private String redirectUrl = DEFAULT_REDIRECT_URL;

    @Override
    protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
        Subject subject = getSubject(request, response);
        String redirectUrl = getRedirectUrl(request, response, subject);
        //try/catch added for SHIRO-298:
        try {
            subject.logout();
            Session session = subject.getSession();
            session.stop();
        } catch (SessionException ise) {
            log.debug("Encountered session exception during logout.  This can generally safely be ignored.", ise);
        }
        issueRedirect(request, response, redirectUrl);
        return false;
    }
}
```










