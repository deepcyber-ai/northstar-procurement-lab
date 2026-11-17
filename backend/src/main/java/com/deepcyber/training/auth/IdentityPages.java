package com.deepcyber.training.auth;

import com.deepcyber.training.service.IdentityService;
import jakarta.servlet.http.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.HtmlUtils;
import java.util.Map;

@RestController
public class IdentityPages {
    private final String issuer;
    private final String redirect;
    private final IdentityService identity;
    private final LabAuthorizations grants;
    public IdentityPages(@Value("${lab.oidc-issuer:http://localhost:8080}") String issuer,
                         @Value("${lab.oidc-redirect-uri:http://localhost:8080/callback}") String redirect,
                         IdentityService identity,LabAuthorizations grants) {
        this.issuer=issuer;this.redirect=redirect;this.identity=identity;this.grants=grants;
    }
    @GetMapping("/auth/config") public Map<String,String> config() {
        return Map.of("issuer",issuer,"clientId","northstar-spa","redirectUri",redirect);
    }
    @GetMapping(value="/auth/login",produces=MediaType.TEXT_HTML_VALUE)
    public String login(HttpServletRequest request) {
        CsrfToken csrf=(CsrfToken)request.getAttribute(CsrfToken.class.getName());
        return """
                <!doctype html><html lang="en"><head><meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <title>Northstar Login</title>
                <style>
                *{box-sizing:border-box}
                body{margin:0;background:#091426;color:#eef5ff;font:16px/1.5 system-ui,sans-serif}
                main{max-width:468px;margin:10vh auto;padding:24px}
                h1{margin:0 0 12px;font-size:2.25rem;line-height:1.2;letter-spacing:-.03em}
                .intro{margin:0 0 32px;color:#b4c3d7}
                form{display:grid;gap:20px}
                .field{display:grid;gap:8px;min-width:0}
                label{font-weight:600}
                input,button{font:inherit;border-radius:8px}
                .field input{width:100%%;min-width:0;padding:12px 14px;border:1px solid #53647d;
                background:#101e33;color:#eef5ff}
                input:focus-visible,button:focus-visible{outline:3px solid #63e5d4;outline-offset:3px}
                button{justify-self:start;margin-top:4px;padding:10px 24px;min-height:44px;
                border:1px solid transparent;background:#63e5d4;color:#091426;font-weight:700;cursor:pointer}
                button:hover{background:#8aeee1}
                [role=alert]{margin:24px 0 0;color:#ffc1cb}
                </style></head><body><main>
                <h1>Northstar Login</h1><p class="intro">Sign in to Northstar Procurement.</p>
                <form method="post" action="/auth/login">
                <div class="field"><label for="email">Work email</label>
                <input id="email" type="email" name="username" autocomplete="username" required></div>
                <div class="field"><label for="password">Password</label>
                <input id="password" type="password" name="password" autocomplete="current-password" required></div>
                <input type="hidden" name="%s" value="%s"><button type="submit">Sign in</button></form>
                %s</main></body></html>
                """.formatted(HtmlUtils.htmlEscape(csrf.getParameterName()),HtmlUtils.htmlEscape(csrf.getToken()),
                request.getParameter("error")!=null?"<p role=alert>Sign-in failed. Check your credentials.</p>":"");
    }
    @GetMapping(value="/auth/signed-out",produces=MediaType.TEXT_HTML_VALUE)
    public String signedOut(HttpServletRequest request) {
        CsrfToken csrf=(CsrfToken)request.getAttribute(CsrfToken.class.getName());
        return "<!doctype html><html lang=en><title>Northstar sign-out</title><h1>Finish signing out</h1>"
                +"<form method=post action=/auth/clear-session><input type=hidden name=\""
                +HtmlUtils.htmlEscape(csrf.getParameterName())+"\" value=\""+HtmlUtils.htmlEscape(csrf.getToken())
                +"\"><button>Return to sign in</button></form></html>";
    }
    @PostMapping("/auth/session/logout") public Map<String,Boolean> logout(HttpServletRequest request,HttpServletResponse response) {
        var jwt=identity.accessToken(request);
        grants.revoke(jwt.getClaimAsString("sid"));
        var session=request.getSession(false);
        if(session!=null)session.invalidate();
        response.addHeader("Set-Cookie","NORTHSTAR_IDP=; Path=/auth; Max-Age=0; HttpOnly; SameSite=Lax"+(issuer.startsWith("https:")?"; Secure":""));
        return Map.of("loggedOut",true);
    }
}
