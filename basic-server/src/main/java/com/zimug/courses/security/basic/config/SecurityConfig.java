package com.zimug.courses.security.basic.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * @Author: lvxuan
 * @program:
 * @Date: 2022/1/22 15:07
 * @Version: 1.0
 * @motto: 而后乃将图南
 * @Description: des
 * ░░░░░░░░░░░░░░░░░░░░░░░░▄░░
 * ░░░░░░░░░▐█░░░░░░░░░░░▄▀▒▌░
 * ░░░░░░░░▐▀▒█░░░░░░░░▄▀▒▒▒▐
 * ░░░░░░░▐▄▀▒▒▀▀▀▀▄▄▄▀▒▒▒▒▒▐
 * ░░░░░▄▄▀▒░▒▒▒▒▒▒▒▒▒█▒▒▄█▒▐
 * ░░░▄▀▒▒▒░░░▒▒▒░░░▒▒▒▀██▀▒▌
 * ░░▐▒▒▒▄▄▒▒▒▒░░░▒▒▒▒▒▒▒▀▄▒▒
 * ░░▌░░▌█▀▒▒▒▒▒▄▀█▄▒▒▒▒▒▒▒█▒▐
 * ░▐░░░▒▒▒▒▒▒▒▒▌██▀▒▒░░░▒▒▒▀▄
 * ░▌░▒▄██▄▒▒▒▒▒▒▒▒▒░░░░░░▒▒▒▒
 * ▀▒▀▐▄█▄█▌▄░▀▒▒░░░░░░░░░░▒▒▒
 * You are not expected to understand this
 */
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    /**
     * 配置登陆验证以及资源访问的权限规则
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
//        http.httpBasic()//开启httpbasic认证
//                .and()
//                .authorizeRequests()
//                .anyRequest()
//                .authenticated();//所有请求都需要登录认证才能访问
        http.csrf().disable()//禁用跨站csrf攻击防御
                .formLogin()
                    .loginPage("/login.html")//一旦用户的请求没有权限就跳转到这个页面
                    .loginProcessingUrl("/login")//登录form表单中action的地址
                    .usernameParameter("username")//登录form表单中用户名input输入框的name名，不修改的话默认是username
                    .passwordParameter("password")//登录form表单中密码的input输入框的name名，不修改的话默认是password
                    .defaultSuccessUrl("/")//登录成功后默认的跳转路径-"/index.html"
                .and()
                    .authorizeRequests()
                    .antMatchers("/login.html","/login").permitAll()//不需要登录验证就可以访问的资源路径
                    .antMatchers("/","biz1","/biz2").hasAnyAuthority("ROLE_user","ROLE_admin")//user,admin 角色可以访问的路径
                    .antMatchers("/syslog","/sysuser").hasAnyRole("admin")//admin角色可以访问的路径
//                    .antMatchers("/syslog").hasAuthority("sys:log")
//                    .antMatchers("/sysuser").hasAuthority("sys:user")
                /**
                 * hasAnyAuthority("ROLE_admin") 等价于 hasAnyRole("admin")
                 */

                    .anyRequest().authenticated();
    }

    /**
     * 配置具体的用户
     * @param auth
     * @throws Exception
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("user")
                .password(passwordEncoder().encode("123456"))
                .roles("user")
                .and()
                .withUser("admin")
                .password(passwordEncoder().encode("123456"))
                .roles("admin")
//                .authorities("sys:log","sys:user")
                .and()
                .passwordEncoder(passwordEncoder());
    }

    /**
     * 将项目中静态资源路径开放
     * @param web
     * @throws Exception
     */
    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/css/**","/fonts/**","/img/**","/js/**");
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
}
