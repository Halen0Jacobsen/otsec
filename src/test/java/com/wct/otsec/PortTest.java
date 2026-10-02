package com.wct.otsec;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers;
import java.nio.file.*;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;

@SpringBootTest(properties={"spring.datasource.url=jdbc:h2:mem:port;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1"})
@ActiveProfiles("local")
class PortTest {
    @Autowired OtsecService service;
    @Autowired ReportParser parser;
    @Autowired WebApplicationContext context;
    String fixture(String name) throws Exception { return Files.readString(Path.of("tooling/examples/"+name)); }
    @Test void reportFormatsAndRedaction() throws Exception {
        for(var pair:Map.of("zaproxy","zap-demo.json","dependency-check","dependency-check-demo.json","spotbugs","spotbugs-demo.xml","find-sec-bugs","spotbugs-demo.xml","sonarqube","sonarqube-demo.json").entrySet()) assertFalse(parser.parse(pair.getKey(),fixture(pair.getValue())).isEmpty());
        var row=parser.parse("zaproxy","{\"site\":[{\"@name\":\"https://u:p@example.com/path?secret=x#fragment\",\"alerts\":[{\"name\":\"test\",\"riskcode\":\"2\",\"pluginid\":\"1\"}]}]}").getFirst();
        assertEquals("https://example.com/path",row.resource());
        assertThrows(IllegalArgumentException.class,() -> parser.parse("spotbugs","<!DOCTYPE x [<!ENTITY e SYSTEM 'file:///secret'>]><BugCollection/>"));
        assertThrows(IllegalArgumentException.class,() -> parser.parse("sonarqube","{\"issues\":[false]}"));
    }
    @Test void atomicImportsDedupScopeAndProduction() throws Exception {
        service.environment("port-lab","lab","192.168.10.0/24");
        String report=fixture("dependency-check-demo.json");
        var imported=service.evidence("port-lab","dependency-check","Demo",report);
        assertTrue((int)imported.get("imported")>0);
        assertEquals(0,service.evidence("port-lab","dependency-check","Demo",report).get("imported"));
        String conn=fixture("conn.jsonl");
        assertTrue((int)service.evidence("port-lab","zeek",null,conn).get("imported")>0);
        assertEquals(0,service.evidence("port-lab","zeek",null,conn).get("imported"));
        var before=service.snapshot().get("counts");
        assertThrows(IllegalArgumentException.class,() -> service.evidence("port-lab","zeek",null,conn+"\n{}"));
        assertEquals(before,service.snapshot().get("counts"));
        service.environment("port-production","production","10.0.0.0/24");
        assertEquals("blocked-by-policy",service.plan("port-production","zaproxy","scan","10.0.0.4").get("state"));
        assertThrows(IllegalArgumentException.class,() -> service.plan("port-production","zaproxy","scan","10.0.1.4"));
        assertThrows(IllegalArgumentException.class,() -> service.environment("bad","lab","10.0.0.1/24"));
        assertThrows(IllegalArgumentException.class,() -> Scope.address("example.com"));
    }
    @Test void httpCsrfAndStaticContract() throws Exception {
        MockMvc mvc=MockMvcBuilders.webAppContextSetup(context).apply(SecurityMockMvcConfigurers.springSecurity()).build();
        mvc.perform(get("/api/status")).andExpect(status().isOk()).andExpect(jsonPath("$.tools[0].id").value("zeek"));
        mvc.perform(get("/api/csrf")).andExpect(status().isOk()).andExpect(jsonPath("$.token").isNotEmpty());
        mvc.perform(post("/api/environments").contentType("application/json").content("{\"name\":\"http-env\",\"mode\":\"lab\",\"cidr\":\"10.3.0.0/24\"}")).andExpect(status().isForbidden());
        mvc.perform(post("/api/environments").with(csrf()).contentType("application/json").content("{\"name\":\"http-env\",\"mode\":\"lab\",\"cidr\":\"10.3.0.0/24\"}")).andExpect(status().isOk()).andExpect(jsonPath("$.result.name").value("http-env"));
        mvc.perform(get("/style.css")).andExpect(status().isOk());
    }
}
