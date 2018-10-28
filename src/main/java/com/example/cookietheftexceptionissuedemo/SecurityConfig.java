package com.example.cookietheftexceptionissuedemo;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.rememberme.InMemoryTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

/**
 * @author Igor Rybak
 * @since 28-Oct-2018
 */
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .formLogin()
                    .loginPage("/login.html").defaultSuccessUrl("/", true)
                    .loginProcessingUrl("/login_processing").permitAll()
                .and()
                .authorizeRequests()
                    .antMatchers("/", "/hello").authenticated()
                .and()
                .rememberMe()
                    .alwaysRemember(true)
                    .tokenRepository(getTokenRepository());
    }

    @Bean
    public PersistentTokenRepository getTokenRepository() {
        return new InMemoryTokenRepositoryImpl();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("user").password("{noop}1234").authorities("ROLE_USER");
    }
}
