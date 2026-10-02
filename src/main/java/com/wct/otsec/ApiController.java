package com.wct.otsec;

import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.dao.DataIntegrityViolationException;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class ApiController {
    private final OtsecService service;
    ApiController(OtsecService service) { this.service=service; }
    @GetMapping("/csrf") Map<String,String> csrf(CsrfToken token) { return Map.of("headerName",token.getHeaderName(),"token",token.getToken()); }
    @GetMapping("/status") Map<String,Object> status() { return service.snapshot(); }
    @PostMapping("/environments") Map<String,Object> environment(@RequestBody Map<String,String> body) { return Map.of("result",service.environment(body.get("name"),body.get("mode"),body.get("cidr"))); }
    @PostMapping("/import") Map<String,Object> evidence(@RequestBody Map<String,String> body) { return Map.of("result",service.evidence(body.get("environment"),body.get("tool"),body.get("application"),body.get("content"))); }
    @PostMapping("/plans") Map<String,Object> plan(@RequestBody Map<String,String> body) { return Map.of("result",service.plan(body.get("environment"),body.get("tool"),body.get("action"),body.get("target"))); }
    @ExceptionHandler(IllegalArgumentException.class) ResponseEntity<?> invalid(IllegalArgumentException e) { return ResponseEntity.badRequest().body(Map.of("error",e.getMessage())); }
    @ExceptionHandler(DataIntegrityViolationException.class) ResponseEntity<?> conflict() { return ResponseEntity.status(409).body(Map.of("error","Record conflicts with existing state; transaction rolled back")); }
}
