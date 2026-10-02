package com.wct.otsec;

import java.util.*;
import org.springframework.context.annotation.*;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

@Configuration
public class SecurityConfig {
    SecurityConfig(org.springframework.core.env.Environment environment) {
        boolean local=environment.acceptsProfiles(org.springframework.core.env.Profiles.of("local"));
        boolean enterprise=environment.acceptsProfiles(org.springframework.core.env.Profiles.of("enterprise"));
        if(local==enterprise) throw new IllegalStateException("Activate exactly one of local or enterprise");
        if(enterprise) {
            String issuer=environment.getRequiredProperty("spring.security.oauth2.client.provider.keycloak.issuer-uri");
            if(!issuer.startsWith("https://")) throw new IllegalStateException("Enterprise OIDC issuer must use HTTPS");
        }
    }
    @Bean @Profile("local")
    SecurityFilterChain local(HttpSecurity http) throws Exception {
        return http.authorizeHttpRequests(a -> a.anyRequest().permitAll()).build();
    }
    @Bean @Profile("enterprise")
    SecurityFilterChain enterprise(HttpSecurity http) throws Exception {
        OidcUserService delegate=new OidcUserService();
        http.redirectToHttps(c -> {});
        http.authorizeHttpRequests(a -> a
            .requestMatchers("/oauth2/**","/login/**","/error").permitAll()
            .requestMatchers(org.springframework.http.HttpMethod.POST,"/api/environments").hasRole("ADMIN")
            .requestMatchers(org.springframework.http.HttpMethod.POST,"/api/**").hasAnyRole("OPERATOR","ADMIN")
            .anyRequest().hasAnyRole("VIEWER","OPERATOR","ADMIN"))
            .oauth2Login(o -> o.userInfoEndpoint(u -> u.oidcUserService(request -> {
                var user=delegate.loadUser(request);
                var authorities=new ArrayList<org.springframework.security.core.GrantedAuthority>(user.getAuthorities());
                Object claim=user.getClaim("realm_access");
                if(claim instanceof Map<?,?> realm && realm.get("roles") instanceof Collection<?> roles)
                    for(Object role:roles) if(Set.of("VIEWER","OPERATOR","ADMIN").contains(role)) authorities.add(new SimpleGrantedAuthority("ROLE_"+role));
                return new DefaultOidcUser(authorities,user.getIdToken(),user.getUserInfo(),"sub");
            })))
            .exceptionHandling(e -> e.defaultAuthenticationEntryPointFor((request,response,exception) -> response.sendError(401), request -> request.getRequestURI().startsWith("/api/")));
        return http.build();
    }
}
