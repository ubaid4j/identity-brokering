package dev.ubaid.apigateway.resources;

import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.net.URI;

@RestController
@RequestMapping("/")
public class IndexResource {

    @GetMapping
    public Mono<Void> index(ServerHttpResponse res) {
        res.setStatusCode(HttpStatus.PERMANENT_REDIRECT);
        res.getHeaders().setLocation(URI.create("/user"));
        return res.setComplete();
    }
}
