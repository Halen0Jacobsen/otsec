package com.wct.otsec;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.*;
import org.springframework.mock.env.MockEnvironment;
import static org.junit.jupiter.api.Assertions.*;

class RequestBoundaryTest {
    MockEnvironment local() { var env=new MockEnvironment(); env.setActiveProfiles("local"); return env; }
    @Test void hostOriginAndBodyLimits() throws Exception {
        var filter=new RequestBoundary(local());
        var request=new MockHttpServletRequest("POST","/api/import");
        request.setLocalPort(8080); request.addHeader("Host","evil.example:8080");
        var response=new MockHttpServletResponse();
        filter.doFilter(request,response,new MockFilterChain()); assertEquals(403,response.getStatus());
        request=new MockHttpServletRequest("POST","/api/import"); request.setLocalPort(8080); request.addHeader("Host","127.0.0.1:8080"); request.addHeader("Origin","http://evil.example");
        response=new MockHttpServletResponse(); filter.doFilter(request,response,new MockFilterChain()); assertEquals(403,response.getStatus());
        request=new MockHttpServletRequest("POST","/api/import"); request.setLocalPort(8080); request.addHeader("Host","127.0.0.1:8080"); request.setContentType("application/json"); request.setContent(new byte[6*1024*1024+1]);
        response=new MockHttpServletResponse(); filter.doFilter(request,response,new MockFilterChain()); assertEquals(413,response.getStatus());
    }
    @Test void conflictingProfilesFailClosed() {
        var env=local(); env.setActiveProfiles("local","enterprise");
        assertThrows(IllegalStateException.class,() -> new SecurityConfig(env));
        env.setActiveProfiles("enterprise"); env.setProperty("spring.security.oauth2.client.provider.keycloak.issuer-uri","http://identity.example");
        assertThrows(IllegalStateException.class,() -> new SecurityConfig(env));
    }
}
