package com.kotkot.myDemo.security;


import com.kotkot.myDemo.auth.UserInfoServiceImpl;
import com.kotkot.myDemo.jwt.JwtTokenVerifier;
import com.kotkot.myDemo.jwt.JwtUsernameAndPasswordAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {
    private final PasswordEncoder passwordEncoder;
    private final UserInfoServiceImpl userInfoService;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder, UserInfoServiceImpl userInfoService) {
        this.passwordEncoder = passwordEncoder;
        this.userInfoService = userInfoService;
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(this.authenticationManager()))
                .addFilterAfter(new JwtTokenVerifier(), JwtUsernameAndPasswordAuthenticationFilter.class)
                .authorizeRequests()
                .antMatchers("/", "/index", "/css/*", "/js/*", "/login", "/home")
                .permitAll()
                .anyRequest().authenticated();

//                        .and().
//                formLogin().loginPage("/login").
//                defaultSuccessUrl("/api/home", true).and().
//                rememberMe().and().logout().logoutUrl("/logout")
//                .clearAuthentication(true).invalidateHttpSession(true).deleteCookies("JSESSIONID", "remember-me").logoutSuccessUrl("/login")
    }


    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(daoAuthenticationProvider());
    }

    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(userInfoService);
        return provider;
    }
}
