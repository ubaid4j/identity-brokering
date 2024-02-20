package dev.ubaid.apigateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.DefaultServerRedirectStrategy;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.ServerRedirectStrategy;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.Objects;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {
    
    private static final Customizer<ServerHttpSecurity.AuthorizeExchangeSpec> AUTHORIZE_EXCHANGE = spec -> spec
            .pathMatchers(HttpMethod.GET, "/favicon.ico")
            .permitAll()
            .anyExchange()
            .authenticated();
    
    private static final Customizer<ServerHttpSecurity.ExceptionHandlingSpec> EXCEPTION_HANDLING = spec -> spec
            .authenticationEntryPoint(new RedirectServerAuthenticationEntryPoint("/oauth2/authorization/customer1"));

    private static final ServerRedirectStrategy redirectStrategy = new DefaultServerRedirectStrategy();
    
    private static final Customizer<ServerHttpSecurity.OAuth2LoginSpec> login = spec -> spec
            .authenticationSuccessHandler(new OnLoginSuccess());

    static class OnLoginSuccess implements ServerAuthenticationSuccessHandler {
        @Override
        public Mono<Void> onAuthenticationSuccess(WebFilterExchange webFilterExchange, Authentication authentication) {
            ServerWebExchange exchange = webFilterExchange.getExchange();
            return exchange
                    .getSession()
                    .flatMap(session -> redirectStrategy.sendRedirect(exchange, URI.create("/user")));

        }
    }
    
    
    @Bean
    SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        return http
                .authorizeExchange(AUTHORIZE_EXCHANGE)
                .oauth2Login(login)
                .exceptionHandling(EXCEPTION_HANDLING)
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .build();
    }
}
