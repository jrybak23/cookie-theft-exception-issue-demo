package com.example.cookietheftexceptionissuedemo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.web.authentication.rememberme.InvalidCookieException;
import org.springframework.security.web.authentication.rememberme.PersistentRememberMeToken;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Base64;
import java.util.Optional;

import static org.springframework.security.web.authentication.rememberme.AbstractRememberMeServices.SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY;

/**
 * @author Igor Rybak
 * @since 28-Oct-2018
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class RememberMeTokenValueUpdaterFilter implements Filter {
    private static final Logger logger = LoggerFactory.getLogger(RememberMeTokenValueUpdaterFilter.class);
    private static final String DELIMITER = ":";
    private static final Duration DURATION_AFTER_LAST_AUTO_LOGIN = Duration.ofMinutes(1);
    private final PersistentTokenRepository repository;

    @Autowired
    public RememberMeTokenValueUpdaterFilter(PersistentTokenRepository repository) {
        this.repository = repository;
    }

    @Override
    public void init(FilterConfig filterConfig) {
    }

    @Override
    public void doFilter(ServletRequest servletRequest,
                         ServletResponse servletResponse,
                         FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        extractRememberMeCookie(request).ifPresent(rememberMeCookie -> {
            String[] cookieTokens = decodeCookie(rememberMeCookie.getValue());

            String presentedSeries = cookieTokens[0];
            String presentedToken = cookieTokens[1];

            PersistentRememberMeToken token = repository.getTokenForSeries(presentedSeries);

            if (token != null
                    && rememberMeCookieValueIsDifferentFromDatabase(presentedToken, token)
                    && aLotOfTimeHasNotPassed(token)) {
                String newRememberMeCookieValue = encodeCookie(new String[]{presentedSeries, token.getTokenValue()});
                rememberMeCookie.setValue(newRememberMeCookieValue);
            }
        });

        filterChain.doFilter(request, response);
    }

    private boolean aLotOfTimeHasNotPassed(PersistentRememberMeToken token) {
        return Duration.of(System.currentTimeMillis() - token.getDate().getTime(), ChronoUnit.MILLIS)
                .compareTo(DURATION_AFTER_LAST_AUTO_LOGIN) < 0;
    }

    private boolean rememberMeCookieValueIsDifferentFromDatabase(String presentedToken, PersistentRememberMeToken token) {
        return !presentedToken.equals(token.getTokenValue());
    }

    private Optional<Cookie> extractRememberMeCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return Optional.empty();
        }
        return Arrays.stream(cookies)
                .filter(cookie -> cookie.getName().equals(SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY))
                .findFirst();
    }

    @Override
    public void destroy() {
    }

    private String[] decodeCookie(String cookieValue) throws InvalidCookieException {
        StringBuilder cookieValueBuilder = new StringBuilder(cookieValue);
        for (int j = 0; j < cookieValueBuilder.length() % 4; j++) {
            cookieValueBuilder.append("=");
        }
        cookieValue = cookieValueBuilder.toString();

        try {
            Base64.getDecoder().decode(cookieValue.getBytes());
        } catch (IllegalArgumentException e) {
            throw new InvalidCookieException("Cookie token was not Base64 encoded; value was '" + cookieValue + "'");
        }

        String cookieAsPlainText = new String(Base64.getDecoder().decode(cookieValue.getBytes()));

        String[] tokens = StringUtils.delimitedListToStringArray(cookieAsPlainText, DELIMITER);

        for (int i = 0; i < tokens.length; i++) {
            try {
                tokens[i] = URLDecoder.decode(tokens[i], StandardCharsets.UTF_8.toString());
            } catch (UnsupportedEncodingException e) {
                logger.error(e.getMessage(), e);
            }
        }

        return tokens;
    }

    private String encodeCookie(String[] cookieTokens) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < cookieTokens.length; i++) {
            try {
                sb.append(URLEncoder.encode(cookieTokens[i], StandardCharsets.UTF_8.toString()));
            } catch (UnsupportedEncodingException e) {
                logger.error(e.getMessage(), e);
            }

            if (i < cookieTokens.length - 1) {
                sb.append(DELIMITER);
            }
        }

        String value = sb.toString();

        sb = new StringBuilder(new String(Base64.getEncoder().encode(value.getBytes())));

        while (sb.charAt(sb.length() - 1) == '=') {
            sb.deleteCharAt(sb.length() - 1);
        }

        return sb.toString();
    }

}
