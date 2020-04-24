/**
 * Copyright © 2016-2020 The Thingsboard Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.thingsboard.server.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpRequest;
import org.springframework.http.MediaType;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.RequestEnhancer;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.MultiValueMap;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;
import org.thingsboard.server.dao.audit.AuditLogLevelFilter;
import org.thingsboard.server.exception.ThingsboardErrorResponseHandler;
import org.thingsboard.server.service.security.auth.jwt.JwtAuthenticationProvider;
import org.thingsboard.server.service.security.auth.jwt.JwtTokenAuthenticationProcessingFilter;
import org.thingsboard.server.service.security.auth.jwt.RefreshTokenAuthenticationProvider;
import org.thingsboard.server.service.security.auth.jwt.RefreshTokenProcessingFilter;
import org.thingsboard.server.service.security.auth.jwt.SkipPathRequestMatcher;
import org.thingsboard.server.service.security.auth.jwt.extractor.TokenExtractor;
import org.thingsboard.server.service.security.auth.rest.RestAuthenticationProvider;
import org.thingsboard.server.service.security.auth.rest.RestLoginProcessingFilter;
import org.thingsboard.server.service.security.auth.rest.RestPublicLoginProcessingFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled=true)
@Order(SecurityProperties.BASIC_AUTH_ORDER)
public class ThingsboardSecurityConfiguration extends WebSecurityConfigurerAdapter {

    public static final String JWT_TOKEN_HEADER_PARAM = "X-Authorization";
    public static final String JWT_TOKEN_QUERY_PARAM = "token";

    public static final String WEBJARS_ENTRY_POINT = "/webjars/**";
    public static final String DEVICE_API_ENTRY_POINT = "/api/v1/**";
    public static final String FORM_BASED_LOGIN_ENTRY_POINT = "/api/auth/login";
    public static final String PUBLIC_LOGIN_ENTRY_POINT = "/api/auth/login/public";
    public static final String TOKEN_REFRESH_ENTRY_POINT = "/api/auth/token";
    protected static final String[] NON_TOKEN_BASED_AUTH_ENTRY_POINTS = new String[] {"/index.html", "/assets/**", "/static/**", "/api/noauth/**", "/webjars/**"};
    public static final String TOKEN_BASED_AUTH_ENTRY_POINT = "/api/**";
    public static final String WS_TOKEN_BASED_AUTH_ENTRY_POINT = "/api/ws/**";

    @Autowired private ThingsboardErrorResponseHandler restAccessDeniedHandler;

    @Autowired
    @Qualifier("oauth2AuthenticationSuccessHandler")
    private AuthenticationSuccessHandler oauth2AuthenticationSuccessHandler;

    @Autowired
    @Qualifier("defaultAuthenticationSuccessHandler")
    private AuthenticationSuccessHandler successHandler;

    @Autowired private AuthenticationFailureHandler failureHandler;

    @Autowired private RestAuthenticationProvider restAuthenticationProvider;
    @Autowired private JwtAuthenticationProvider jwtAuthenticationProvider;
    @Autowired private RefreshTokenAuthenticationProvider refreshTokenAuthenticationProvider;


    @Autowired
    @Qualifier("jwtHeaderTokenExtractor")
    private TokenExtractor jwtHeaderTokenExtractor;

    @Autowired
    @Qualifier("jwtQueryTokenExtractor")
    private TokenExtractor jwtQueryTokenExtractor;

    @Autowired private AuthenticationManager authenticationManager;

    @Autowired private ObjectMapper objectMapper;

    @Autowired private RateLimitProcessingFilter rateLimitProcessingFilter;

    @Bean
    protected RestLoginProcessingFilter buildRestLoginProcessingFilter() throws Exception {
        RestLoginProcessingFilter filter = new RestLoginProcessingFilter(FORM_BASED_LOGIN_ENTRY_POINT, successHandler, failureHandler, objectMapper);
        filter.setAuthenticationManager(this.authenticationManager);
        return filter;
    }

    @Bean
    protected RestPublicLoginProcessingFilter buildRestPublicLoginProcessingFilter() throws Exception {
        RestPublicLoginProcessingFilter filter = new RestPublicLoginProcessingFilter(PUBLIC_LOGIN_ENTRY_POINT, successHandler, failureHandler, objectMapper);
        filter.setAuthenticationManager(this.authenticationManager);
        return filter;
    }

    protected JwtTokenAuthenticationProcessingFilter buildJwtTokenAuthenticationProcessingFilter() throws Exception {
        List<String> pathsToSkip = new ArrayList(Arrays.asList(NON_TOKEN_BASED_AUTH_ENTRY_POINTS));
        pathsToSkip.addAll(Arrays.asList(WS_TOKEN_BASED_AUTH_ENTRY_POINT, TOKEN_REFRESH_ENTRY_POINT, FORM_BASED_LOGIN_ENTRY_POINT,
                PUBLIC_LOGIN_ENTRY_POINT, DEVICE_API_ENTRY_POINT, WEBJARS_ENTRY_POINT));
        SkipPathRequestMatcher matcher = new SkipPathRequestMatcher(pathsToSkip, TOKEN_BASED_AUTH_ENTRY_POINT);
        JwtTokenAuthenticationProcessingFilter filter
                = new JwtTokenAuthenticationProcessingFilter(failureHandler, jwtHeaderTokenExtractor, matcher);
        filter.setAuthenticationManager(this.authenticationManager);
        return filter;
    }

    @Bean
    protected RefreshTokenProcessingFilter buildRefreshTokenProcessingFilter() throws Exception {
        RefreshTokenProcessingFilter filter = new RefreshTokenProcessingFilter(TOKEN_REFRESH_ENTRY_POINT, successHandler, failureHandler, objectMapper);
        filter.setAuthenticationManager(this.authenticationManager);
        return filter;
    }

    @Bean
    protected JwtTokenAuthenticationProcessingFilter buildWsJwtTokenAuthenticationProcessingFilter() throws Exception {
        AntPathRequestMatcher matcher = new AntPathRequestMatcher(WS_TOKEN_BASED_AUTH_ENTRY_POINT);
        JwtTokenAuthenticationProcessingFilter filter
                = new JwtTokenAuthenticationProcessingFilter(failureHandler, jwtQueryTokenExtractor, matcher);
        filter.setAuthenticationManager(this.authenticationManager);
        return filter;
    }


    static class AcceptJsonRequestInterceptor implements ClientHttpRequestInterceptor {

        @Override
        public ClientHttpResponse intercept(HttpRequest request, byte[] body,
                                            ClientHttpRequestExecution execution) throws IOException {
            request.getHeaders().setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
            return execution.execute(request, body);
        }

    }

    static class AcceptJsonRequestEnhancer implements RequestEnhancer {

        @Override
        public void enhance(AccessTokenRequest request,
                            OAuth2ProtectedResourceDetails resource,
                            MultiValueMap<String, String> form, HttpHeaders headers) {
            headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
        }

    }


//    @Bean
//    protected OAuth2LoginAuthenticationFilter buildOAuth2ClientAuthenticationProcessingFilter() throws Exception {
//        AuthorizationCodeResourceDetails details = new AuthorizationCodeResourceDetails();
//        details.setClientId("dVH9reqyqiXIG7M2wmamb0ySue8zaM4g");
//        details.setUserAuthorizationUri("https://dev-r9m8ht0k.auth0.com/authorize");
//        details.setAccessTokenUri("https://dev-r9m8ht0k.auth0.com/oauth/token");
//
//        OAuth2RestTemplate restTemplate = new OAuth2RestTemplate(details);
//        restTemplate.getInterceptors().add(new AcceptJsonRequestInterceptor());
//        AuthorizationCodeAccessTokenProvider accessTokenProvider = new AuthorizationCodeAccessTokenProvider();
//        accessTokenProvider.setTokenRequestEnhancer(new AcceptJsonRequestEnhancer());
//        restTemplate.setAccessTokenProvider(accessTokenProvider);
//        OAuth2LoginAuthenticationFilter filter
//                = new OAuth2LoginAuthenticationFilter(SSO_LOGIN_ENTRY_POINT);
//        filter.setRestTemplate(restTemplate);
//        filter.setAuthenticationManager(this.authenticationManager);
//        return filter;
//    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(restAuthenticationProvider);
        auth.authenticationProvider(jwtAuthenticationProvider);
        auth.authenticationProvider(refreshTokenAuthenticationProvider);
    }

    @Bean
    protected BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/*.js","/*.css","/*.ico","/assets/**","/static/**");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.headers().cacheControl().and().frameOptions().disable()
                .and()
                .cors()
                .and()
                .csrf().disable()
                .exceptionHandling()
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
                .antMatchers(WEBJARS_ENTRY_POINT).permitAll() // Webjars
                .antMatchers(DEVICE_API_ENTRY_POINT).permitAll() // Device HTTP Transport API
                .antMatchers(FORM_BASED_LOGIN_ENTRY_POINT).permitAll() // Login end-point
                .antMatchers(PUBLIC_LOGIN_ENTRY_POINT).permitAll() // Public login end-point
                .antMatchers(TOKEN_REFRESH_ENTRY_POINT).permitAll() // Token refresh end-point
                .antMatchers(NON_TOKEN_BASED_AUTH_ENTRY_POINTS).permitAll() // static resources, user activation and password reset end-points
                .and()
                .authorizeRequests()
                .antMatchers(WS_TOKEN_BASED_AUTH_ENTRY_POINT).authenticated() // Protected WebSocket API End-points
                .antMatchers(TOKEN_BASED_AUTH_ENTRY_POINT).authenticated() // Protected API End-points
                .and()
                .exceptionHandling().accessDeniedHandler(restAccessDeniedHandler)
                .and()
                .addFilterBefore(buildRestLoginProcessingFilter(), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(buildRestPublicLoginProcessingFilter(), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(buildJwtTokenAuthenticationProcessingFilter(), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(buildRefreshTokenProcessingFilter(), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(buildWsJwtTokenAuthenticationProcessingFilter(), UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(rateLimitProcessingFilter, UsernamePasswordAuthenticationFilter.class)
                .oauth2Login()
//                .successHandler(successHandler)
                .successHandler(oauth2AuthenticationSuccessHandler);
//                .redirectionEndpoint()
//                .baseUri("/oauth2/redirect")
//                .and();
    }

//    @Bean
//    public ClientRegistrationRepository clientRegistrationRepository(@Autowired Oauth2Settings settings) {
//        ClientRegistration registration = ClientRegistration.withRegistrationId("A")
//                 .clientId("d9a55511-2f9d-407f-886d-3b3d6a1c2e3f")
//                .authorizationUri("https://idp-q.schwarz/nidp/oauth/nam/authz")
//                .clientSecret("4bJ-WvIWEXyiDebLKRYWPqEaTv001SFpkSdVnZd_wIcyXEAhQuKsPbji2Do8two2jpeyPATJZepDd4olosmNbA")
//                .tokenUri("https://idp-q.schwarz/nidp/oauth/nam/token")
//                .redirectUriTemplate("http://localhost:8080/login/oauth2/code/")
//                .scope("openid,profile,email,siam".split(","))
//                .clientName("Thingsboard Dev Test Q")
//                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//                .userInfoUri("https://idp-q.schwarz/nidp/oauth/nam/userinfo")
//                .userNameAttributeName("email")
////                .jwkSetUri("https://dev-r9m8ht0k.auth0.com/.well-known/jwks.json")
//                .clientAuthenticationMethod(ClientAuthenticationMethod.POST)
//                .build();
//
//        return new InMemoryClientRegistrationRepository(Arrays.asList(registration));
//    }

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository(@Autowired Oauth2Settings settings) {
        ClientRegistration registration = ClientRegistration.withRegistrationId("A")
                 .clientId("dVH9reqyqiXIG7M2wmamb0ySue8zaM4g")
                .authorizationUri("https://dev-r9m8ht0k.auth0.com/authorize")
                .clientSecret("EYAfAGxwkwoeYnb2o2cDgaWZB5k97OStpZQPPvcMMD-SVH2BuughTGeBazXtF5I6")
                .tokenUri("https://dev-r9m8ht0k.auth0.com/oauth/token")
                .redirectUriTemplate("http://localhost:8080/login/oauth2/code/")
                .scope("openid,profile,email".split(","))
                .clientName("Test app")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .userInfoUri("https://dev-r9m8ht0k.auth0.com/userinfo")
                .userNameAttributeName("email")
                .jwkSetUri("https://dev-r9m8ht0k.auth0.com/.well-known/jwks.json")
                .clientAuthenticationMethod(ClientAuthenticationMethod.POST)
                .build();

        return new InMemoryClientRegistrationRepository(Arrays.asList(registration));
    }

    @Bean
    @ConditionalOnMissingBean(CorsFilter.class)
    public CorsFilter corsFilter(@Autowired MvcCorsProperties mvcCorsProperties) {
        if (mvcCorsProperties.getMappings().size() == 0) {
            return new CorsFilter(new UrlBasedCorsConfigurationSource());
        } else {
            UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
            source.setCorsConfigurations(mvcCorsProperties.getMappings());
            return new CorsFilter(source);
        }
    }

    @Bean
    public AuditLogLevelFilter auditLogLevelFilter(@Autowired AuditLogLevelProperties auditLogLevelProperties) {
        return new AuditLogLevelFilter(auditLogLevelProperties.getMask());
    }
}
