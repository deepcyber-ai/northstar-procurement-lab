package com.deepcyber.training;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = {
        "lab.allowed-origin-patterns=https://d111111abcdef8.cloudfront.net, https://app.example.test"
})
@AutoConfigureMockMvc
class WebConfigPropertyTests {

    @Autowired MockMvc mvc;

    @Test
    void acceptsEachConfiguredCloudOriginPattern() throws Exception {
        mvc.perform(options("/api/orders")
                        .header("Origin", "https://d111111abcdef8.cloudfront.net")
                        .header("Access-Control-Request-Method", "GET"))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Origin",
                        "https://d111111abcdef8.cloudfront.net"));

        mvc.perform(options("/api/orders")
                        .header("Origin", "https://app.example.test")
                        .header("Access-Control-Request-Method", "GET"))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Origin", "https://app.example.test"));
        mvc.perform(options("/api/orders/ORD-A-100/notes")
                        .header("Origin", "https://app.example.test")
                        .header("Access-Control-Request-Method", "PUT"))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Methods", org.hamcrest.Matchers.containsString("PUT")));
    }

    @Test
    void rejectsAnOriginOutsideTheConfiguredPatterns() throws Exception {
        mvc.perform(options("/api/orders")
                        .header("Origin", "https://untrusted.example.test")
                        .header("Access-Control-Request-Method", "GET"))
                .andExpect(status().isForbidden());
    }
}
