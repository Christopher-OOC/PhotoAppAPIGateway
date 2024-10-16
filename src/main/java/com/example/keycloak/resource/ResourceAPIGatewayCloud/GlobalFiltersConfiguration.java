package com.example.keycloak.resource.ResourceAPIGatewayCloud;

import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class GlobalFiltersConfiguration {

    @Bean
    public GlobalFilter secondPreFilter() {

        return ((exchange, chain) -> {

            return chain.filter(exchange);
        });

    }

}
