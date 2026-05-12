package org.mcc.vulfr.config;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FilterConfig {
    
    @Bean
    public FilterRegistrationBean<SecurityHeadersConfig> securityHeadersFilter() {
        FilterRegistrationBean<SecurityHeadersConfig> registrationBean = new FilterRegistrationBean<>();
        registrationBean.setFilter(new SecurityHeadersConfig());
        registrationBean.addUrlPatterns("/*");
        registrationBean.setOrder(1);
        return registrationBean;
    }
}
