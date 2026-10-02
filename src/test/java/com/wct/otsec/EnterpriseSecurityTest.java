package com.wct.otsec;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.oauth2.client.registration.*;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(properties={"spring.datasource.url=jdbc:h2:mem:enterprise;DATABASE_TO_LOWER=TRUE", "spring.datasource.username=sa", "spring.datasource.password=", "spring.security.oauth2.client.provider.keycloak.issuer-uri=https://identity.invalid/realm", "spring.security.oauth2.client.registration.keycloak.client-id=test", "spring.security.oauth2.client.registration.keycloak.client-secret=test"})
@ActiveProfiles("enterprise")
@Import(EnterpriseSecurityTest.IdentityStub.class)
class EnterpriseSecurityTest {
    @TestConfiguration static class IdentityStub {
        @Bean ClientRegistrationRepository registrations() {
            return new InMemoryClientRegistrationRepository(ClientRegistration.withRegistrationId("keycloak").clientId("test").clientSecret("test").authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).redirectUri("{baseUrl}/login/oauth2/code/{registrationId}").scope("openid","profile").authorizationUri("https://identity.invalid/auth").tokenUri("https://identity.invalid/token").jwkSetUri("https://identity.invalid/keys").userInfoUri("https://identity.invalid/userinfo").userNameAttributeName("sub").clientName("Test identity").build());
        }
    }
    @Autowired WebApplicationContext context;
    MockMvc mvc() { return MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build(); }
    @Test void anonymousAndHttps() throws Exception {
        mvc().perform(get("https://localhost/api/status").secure(true)).andExpect(status().isUnauthorized());
        mvc().perform(get("/api/status")).andExpect(status().is3xxRedirection());
    }
    @Test @WithMockUser(roles="VIEWER") void viewerCannotWrite() throws Exception {
        mvc().perform(get("https://localhost/api/status").secure(true)).andExpect(status().isOk());
        mvc().perform(post("https://localhost/api/environments").secure(true).with(csrf()).contentType("application/json").content("{}")).andExpect(status().isForbidden());
        mvc().perform(post("https://localhost/api/import").secure(true).with(csrf()).contentType("application/json").content("{}")).andExpect(status().isForbidden());
    }
    @Test @WithMockUser(roles="OPERATOR") void operatorCannotConfigureEnvironment() throws Exception {
        mvc().perform(post("https://localhost/api/environments").secure(true).with(csrf()).contentType("application/json").content("{}")).andExpect(status().isForbidden());
        mvc().perform(post("https://localhost/api/plans").secure(true).with(csrf()).contentType("application/json").content("{}")).andExpect(status().isBadRequest());
    }
    @Test @WithMockUser(username="enterprise-admin",roles="ADMIN") void adminAuditAndCsrf() throws Exception {
        mvc().perform(post("https://localhost/api/environments").secure(true).contentType("application/json").content("{}")).andExpect(status().isForbidden());
        mvc().perform(post("https://localhost/api/environments").secure(true).with(csrf()).contentType("application/json").content("{\"name\":\"enterprise-env\",\"mode\":\"production\",\"cidr\":\"10.8.0.0/24\"}")).andExpect(status().isOk());
        mvc().perform(get("https://localhost/api/status").secure(true)).andExpect(jsonPath("$.audit[0].actor").value("enterprise-admin"));
    }
}
