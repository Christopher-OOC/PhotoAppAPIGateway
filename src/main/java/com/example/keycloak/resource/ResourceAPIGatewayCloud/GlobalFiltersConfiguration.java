package com.example.keycloak.resource.ResourceAPIGatewayCloud;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class GlobalFiltersConfiguration {

    final Logger logger = LoggerFactory.getLogger(GlobalFiltersConfiguration.class);

    @Bean
    public GlobalFilter secondPreFilter() {

        return ((exchange, chain) -> {

            logger.info("My second global pre-filter is executed...");

            return chain.filter(exchange);
        });

    }

}
