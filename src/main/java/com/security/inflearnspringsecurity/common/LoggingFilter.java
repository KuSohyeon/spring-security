package com.security.inflearnspringsecurity.common;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StopWatch;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

public class LoggingFilter extends GenericFilter {

    private Logger logger = LoggerFactory.getLogger(this.getClass());

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        StopWatch stopWatch = new StopWatch();
        stopWatch.start(((HttpServletRequest)servletRequest).getRequestURI());

        filterChain.doFilter(servletRequest, servletResponse);

        stopWatch.stop();
        logger.info(stopWatch.prettyPrint());
    }
}
