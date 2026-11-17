package com.deepcyber.training.auth;

import com.deepcyber.training.store.LabStore;
import com.deepcyber.training.service.VulnerabilityPolicy;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import org.springframework.beans.factory.annotation.*;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.*;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.authentication.*;
import org.springframework.security.oauth2.server.authorization.client.*;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.*;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.security.web.*;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import java.net.URI;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.*;
import java.util.*;

@Configuration
public class OidcConfiguration {
    @Value("${lab.oidc-issuer:http://localhost:8080}") String issuer;
    @Value("${lab.oidc-redirect-uri:http://localhost:8080/callback}") String redirect;
    @Value("${lab.access-token-ttl:86400}") long accessTtl;
    @Value("${lab.refresh-token-ttl:604800}") long refreshTtl;

    @Bean PasswordEncoder passwordEncoder() { return new BCryptPasswordEncoder(); }
    @Bean javax.sql.DataSource identityDataSource(IdentityDatabase database) { return database.jdbc.getDataSource(); }
    @Bean RegisteredClientRepository clients() {
        URI url=URI.create(issuer);
        if (!"https".equals(url.getScheme()) && !("http".equals(url.getScheme()) &&
                Set.of("localhost","127.0.0.1").contains(url.getHost())))
            throw new IllegalStateException("Issuer must use HTTPS except loopback development");
        if (accessTtl<=0 || refreshTtl<=accessTtl) throw new IllegalStateException("Invalid token lifetimes");
        return new InMemoryRegisteredClientRepository(RegisteredClient.withId("northstar-spa")
                .clientId("northstar-spa").clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri(redirect).postLogoutRedirectUri(issuer+"/login")
                .scope("openid").scope("profile").scope("offline_access").scope("northstar.api")
                .clientSettings(ClientSettings.builder().requireProofKey(true).requireAuthorizationConsent(false).build())
                .tokenSettings(TokenSettings.builder().authorizationCodeTimeToLive(Duration.ofMinutes(2))
                        .accessTokenTimeToLive(Duration.ofSeconds(accessTtl)).refreshTokenTimeToLive(Duration.ofSeconds(refreshTtl))
                        .reuseRefreshTokens(false).build()).build());
    }
    @Bean LabAuthorizations authorizations(IdentityDatabase db, RegisteredClientRepository clients) {
        return new LabAuthorizations(db,clients);
    }
    @Bean AuthorizationServerSettings settings() {
        return AuthorizationServerSettings.builder().issuer(issuer)
                .authorizationEndpoint("/auth/authorize").tokenEndpoint("/auth/token")
                .jwkSetEndpoint("/auth/jwks").tokenRevocationEndpoint("/auth/revoke")
                .tokenIntrospectionEndpoint("/auth/introspect")
                .oidcUserInfoEndpoint("/auth/userinfo").oidcLogoutEndpoint("/auth/logout").build();
    }
    @Bean RSAKey signingKey(@Value("${lab.signing-key-path:./keys/signing.jwk}") String location) throws Exception {
        Path path=Path.of(location);
        Files.createDirectories(path.toAbsolutePath().getParent());
        if (!Files.exists(path)) {
            RSAKey generated=new RSAKeyGenerator(3072).keyID(UUID.randomUUID().toString()).generate();
            Files.createFile(path,PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
            Files.writeString(path,generated.toJSONString());
        }
        Files.setPosixFilePermissions(path,PosixFilePermissions.fromString("rw-------"));
        return RSAKey.parse(Files.readString(path));
    }
    @Bean JWKSource<SecurityContext> jwkSource(RSAKey key) {
        return (selector,context) -> selector.select(new JWKSet(key));
    }
    @Bean JwtEncoder jwtEncoder(JWKSource<SecurityContext> keys) { return new NimbusJwtEncoder(keys); }
    @Bean JwtDecoder jwtDecoder(RSAKey key) throws Exception {
        var decoder=NimbusJwtDecoder.withPublicKey(key.toRSAPublicKey()).build();
        decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(issuer));
        return decoder;
    }
    @Bean("apiDecoder") JwtDecoder apiDecoder(RSAKey key, LabAuthorizations grants) throws Exception {
        var decoder=NimbusJwtDecoder.withPublicKey(key.toRSAPublicKey()).build();
        decoder.setJwtValidator(new org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithIssuer(issuer), jwt -> {
                    boolean valid=jwt.getAudience().contains("northstar-api")
                            && jwt.getExpiresAt()!=null
                            && jwt.getClaimAsStringList("scope")!=null
                            && jwt.getClaimAsStringList("scope").contains("northstar.api")
                            && "access".equals(jwt.getClaimAsString("token_use"))
                            && grants.active(jwt.getClaimAsString("sid"));
                    return valid?OAuth2TokenValidatorResult.success():
                            OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token"));
                }));
        return decoder;
    }
    @Bean OAuth2TokenGenerator<?> tokenGenerator(JwtEncoder encoder, LabStore store, LabAuthorizations grants) {
        JwtGenerator jwt=new JwtGenerator(encoder);
        jwt.setJwtCustomizer(context -> {
            var user=store.findUser(context.getPrincipal().getName()).orElseThrow();
            context.getClaims().subject(user.id());
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                context.getClaims().audience(new ArrayList<>(List.of("northstar-api"))).claim("token_use","access")
                        .claim("sid",context.getAuthorization().getId());
            } else {
                context.getClaims().expiresAt(Instant.now().plusSeconds(accessTtl))
                        .claim("name",user.displayName()).claim("email",user.email());
            }
        });
        // Lab extension: Spring's default generator intentionally omits public-client refresh tokens.
        OAuth2TokenGenerator<OAuth2RefreshToken> refresh=context -> {
            if (!OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType())) return null;
            Instant now=Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS), end=grants.expires(context.getAuthorization().getId());
            if (end==null) end=now.plusSeconds(refreshTtl);
            if (!end.isAfter(now)) throw new OAuth2AuthenticationException("invalid_grant");
            byte[] bytes=new byte[48]; new java.security.SecureRandom().nextBytes(bytes);
            return new OAuth2RefreshToken(Base64.getUrlEncoder().withoutPadding().encodeToString(bytes),now,end);
        };
        return new DelegatingOAuth2TokenGenerator(jwt,new OAuth2AccessTokenGenerator(),refresh);
    }
    @Bean @Order(1)
    SecurityFilterChain identityChain(HttpSecurity http, RegisteredClientRepository clients, LabAuthorizations grants,
                                      @Qualifier("apiDecoder") JwtDecoder decoder, VulnerabilityPolicy vulnerabilities) throws Exception {
        var auth=OAuth2AuthorizationServerConfigurer.authorizationServer();
        http.securityMatcher("/auth/**","/.well-known/**")
                .with(auth, server -> server
                        .oidc(Customizer.withDefaults())
                        .clientAuthentication(c -> c.authenticationConverter(LabPublicClientProvider.converter())
                                .authenticationProviders(providers -> {
                                    providers.removeIf(p -> p instanceof PublicClientAuthenticationProvider);
                                    providers.add(0,new LabPublicClientProvider(clients,grants,vulnerabilities));
                                }))
                        .authorizationEndpoint(endpoint -> endpoint.authenticationProviders(providers -> providers.forEach(p -> {
                            if (p instanceof OAuth2AuthorizationCodeRequestAuthenticationProvider provider)
                                provider.setAuthenticationValidator(new OAuth2AuthorizationCodeRequestAuthenticationValidator().andThen(context -> {
                                    OAuth2AuthorizationCodeRequestAuthenticationToken request=context.getAuthentication();
                                    var params=request.getAdditionalParameters();
                                    if (!redirect.equals(request.getRedirectUri()) || !"S256".equals(params.get("code_challenge_method"))
                                            || !(params.get("code_challenge") instanceof String challenge) || !challenge.matches("[A-Za-z0-9_-]{43}"))
                                        throw new OAuth2AuthorizationCodeRequestAuthenticationException(new OAuth2Error("invalid_request"),request);
                                }));
                        }))))
                .authorizeHttpRequests(a -> a.requestMatchers("/auth/login","/auth/config","/auth/signed-out","/.well-known/**","/auth/jwks").permitAll()
                        .anyRequest().authenticated())
                .formLogin(f -> f.loginPage("/auth/login").loginProcessingUrl("/auth/login").permitAll())
                .logout(l -> l.logoutUrl("/auth/clear-session").logoutSuccessUrl(issuer+"/login").deleteCookies("NORTHSTAR_IDP"))
                .exceptionHandling(e -> e.defaultAuthenticationEntryPointFor(new LoginUrlAuthenticationEntryPoint(issuer+"/auth/login"),
                        new MediaTypeRequestMatcher(MediaType.TEXT_HTML)))
                .csrf(c -> c.ignoringRequestMatchers("/auth/session/logout"))
                .oauth2ResourceServer(r -> r.jwt(j -> j.decoder(decoder)));
        return http.build();
    }
    @Bean @Order(2)
    SecurityFilterChain apiChain(HttpSecurity http,@Qualifier("apiDecoder") JwtDecoder decoder) throws Exception {
        http.securityMatcher("/**").csrf(c -> c.disable())
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(a -> a.anyRequest().permitAll())
                .oauth2ResourceServer(r -> r.jwt(j -> j.decoder(decoder)));
        return http.build();
    }
    @Bean FilterRegistrationBean<Filter> protocolBoundary() {
        URI external=URI.create(issuer);
        Object tokenLock=new Object();
        Filter filter=(request,response,chain) -> {
            HttpServletRequest req=(HttpServletRequest)request;
            if (!req.getRequestURI().startsWith("/auth/") && !req.getRequestURI().startsWith("/.well-known/")) {
                chain.doFilter(request,response); return;
            }
            // Fixed external origin: never derive issuer or saved login redirects from untrusted proxy headers.
            var wrapped=new HttpServletRequestWrapper(req) {
                @Override public String getScheme(){return external.getScheme();}
                @Override public String getServerName(){return external.getHost();}
                @Override public int getServerPort(){return external.getPort()==-1?("https".equals(getScheme())?443:80):external.getPort();}
                @Override public boolean isSecure(){return "https".equals(getScheme());}
                @Override public StringBuffer getRequestURL(){return new StringBuffer(issuer+getRequestURI());}
            };
            ((HttpServletResponse)response).setHeader("Cache-Control","no-store");
            ((HttpServletResponse)response).setHeader("Referrer-Policy","no-referrer");
            // Serialise complete exchanges, including framework validation and save, to prevent code/refresh races.
            if (req.getRequestURI().equals("/auth/token")) {
                synchronized(tokenLock) { chain.doFilter(wrapped,response); }
            } else chain.doFilter(wrapped,response);
        };
        var bean=new FilterRegistrationBean<>(filter);
        bean.setOrder(-200);
        return bean;
    }
}
