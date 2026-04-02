package com.apigateway.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;

@Component
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    private static final String SECRET_KEY = "secret12345";  // use for decoding token && must match with AuthService

    private static final List<String> openApiEndpoints = List.of( // list of open uri
            "/auth/api/v1/auth/login",
            "/auth/api/v1/auth/register"
    );

    private static final Map<String, List<String>> protectedEndpointsWithRoles = Map.of(
    	    "/micro1/message", List.of("ROLE_ADMIN")  // storing as key value pair   uri --> role [roles that can access which uri]
        // static ,immutable map that associates API endpoints with the roles allowd to access them.
    	,
    "/micro2/micro2info",List.of("ROLE_USER")
    );


    @Override                 // incoming http Request+ token    // set permission to url when permission is set becomes open url
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String requestPath = exchange.getRequest().getURI().getPath();

        // Allow public endpoints
        if (isPublicEndpoint(requestPath)) {  // isPublicEndpoint is method below
            return chain.filter(exchange);  // open url[accessible] no token required grant permission
            // granting permission to the uri to give access
        }

        String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization"); // JWT Token
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        String token = authHeader.substring(7); //EXTRACT TOKEN

        try {
            DecodedJWT jwt = JWT.require(Algorithm.HMAC256(SECRET_KEY))
                    .build()
                    .verify(token);

            String role = jwt.getClaim("role").asString();  // get role

            System.out.println("Request path: " + requestPath);
            System.out.println("Role from token: " + role);

            if (!isAuthorized(requestPath, role)) { // method to check if role has access to requestPath
                exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                return exchange.getResponse().setComplete();
            } // not accessible

            // Pass role to downstream services (optional)
            exchange = exchange.mutate()
                    .request(r -> r.header("X-User-Role", role))
                    .build();

        } catch (JWTVerificationException e) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        return chain.filter(exchange); // make url open for role
    }

    private boolean isPublicEndpoint(String path) {
        return openApiEndpoints.stream().anyMatch(path::equalsIgnoreCase);  // comparing openApiEndpoints and path [HTTP Request that i made to API Gateway]
        // run for every value
    }
                             // Http Request path
    private boolean isAuthorized(String path, String role) {
        for (Map.Entry<String, List<String>> entry : protectedEndpointsWithRoles.entrySet()) { // entry contains key --> value pair
            String protectedPath = entry.getKey();
            List<String> allowedRoles = entry.getValue();

            if (path.startsWith(protectedPath)) { // compare Http requestpath to protected path
                System.out.println("Matched protected path: " + protectedPath + " | Allowed roles: " + allowedRoles);
                return allowedRoles.contains(role); // roles also checked
            }
        }
        return false; // Allow access if path is not protected (can be changed to false to deny by default)
    }

    @Override
    public int getOrder() {
        return -1;
    }
}
