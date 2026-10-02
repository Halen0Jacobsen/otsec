package com.wct.otsec;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import org.springframework.stereotype.Component;
import org.springframework.core.env.Environment;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.*;

/** Bound requests before JSON deserialization and reject loopback DNS rebinding. */
@Component
public class RequestBoundary extends OncePerRequestFilter {
    private final Environment environment;
    RequestBoundary(Environment environment) { this.environment=environment; }
    @Override protected void doFilterInternal(HttpServletRequest request,HttpServletResponse response,FilterChain chain) throws ServletException,IOException {
        if(environment.acceptsProfiles(org.springframework.core.env.Profiles.of("local"))) {
            String expected="127.0.0.1:"+request.getLocalPort();
            if(!expected.equals(request.getHeader("Host"))) { response.sendError(403); return; }
            String origin=request.getHeader("Origin");
            if(origin!=null && !origin.equals("http://"+expected)) { response.sendError(403); return; }
        }
        if(request.getMethod().equals("POST") && request.getRequestURI().startsWith("/api/")) {
            if(request.getContentType()==null || !request.getContentType().split(";")[0].equalsIgnoreCase("application/json")) { response.sendError(415); return; }
            int max=6*1024*1024;
            if(request.getContentLengthLong()>max) { response.sendError(413); return; }
            byte[] body=request.getInputStream().readNBytes(max+1);
            if(body.length>max) { response.sendError(413); return; }
            request=new HttpServletRequestWrapper(request) {
                @Override public ServletInputStream getInputStream() {
                    var input=new ByteArrayInputStream(body);
                    return new ServletInputStream() {
                        public int read() { return input.read(); }
                        public boolean isFinished() { return input.available()==0; }
                        public boolean isReady() { return true; }
                        public void setReadListener(ReadListener listener) { throw new UnsupportedOperationException(); }
                    };
                }
                @Override public BufferedReader getReader() { return new BufferedReader(new InputStreamReader(getInputStream(),java.nio.charset.StandardCharsets.UTF_8)); }
            };
        }
        chain.doFilter(request,response);
    }
}
