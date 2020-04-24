package org.thingsboard.server.service.security.auth.rest;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.thingsboard.server.common.data.User;
import org.thingsboard.server.common.data.audit.ActionType;
import org.thingsboard.server.common.data.id.TenantId;
import org.thingsboard.server.common.data.security.UserCredentials;
import org.thingsboard.server.dao.audit.AuditLogService;
import org.thingsboard.server.dao.customer.CustomerService;
import org.thingsboard.server.dao.user.UserService;
import org.thingsboard.server.service.security.auth.jwt.RefreshTokenRepository;
import org.thingsboard.server.service.security.model.SecurityUser;
import org.thingsboard.server.service.security.model.UserPrincipal;
import org.thingsboard.server.service.security.model.token.JwtToken;
import org.thingsboard.server.service.security.model.token.JwtTokenFactory;
import org.thingsboard.server.service.security.system.SystemSecurityService;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Component(value="oauth2AuthenticationSuccessHandler")
public class Oauth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final ObjectMapper mapper;
    private final JwtTokenFactory tokenFactory;
    private final RefreshTokenRepository refreshTokenRepository;
    private final SystemSecurityService systemSecurityService;
    private final UserService userService;

    @Autowired
    public Oauth2AuthenticationSuccessHandler(final ObjectMapper mapper, final JwtTokenFactory tokenFactory, final RefreshTokenRepository refreshTokenRepository, final UserService userService,
                                              final SystemSecurityService systemSecurityService) {
        this.mapper = mapper;
        this.tokenFactory = tokenFactory;
        this.refreshTokenRepository = refreshTokenRepository;
        this.userService = userService;
        this.systemSecurityService = systemSecurityService;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        Object object = authentication.getPrincipal();

        UserPrincipal principal = new UserPrincipal(UserPrincipal.Type.USER_NAME, "tenant@thingsboard.org");
        SecurityUser securityUser =  (SecurityUser) authenticateByUsernameAndPassword(principal,"tenant@thingsboard.org", "tenant").getPrincipal();

        JwtToken accessToken = tokenFactory.createAccessJwtToken(securityUser);
        JwtToken refreshToken = refreshTokenRepository.requestRefreshToken(securityUser);

        Map<String, String> tokenMap = new HashMap<String, String>();
        tokenMap.put("token", accessToken.getToken());
        tokenMap.put("refreshToken", refreshToken.getToken());

//        response.setStatus(HttpStatus.OK.value());
//        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
//        mapper.writeValue(response.getWriter(), tokenMap);

        request.setAttribute("token", accessToken.getToken());
        response.addHeader("token", accessToken.getToken());

        getRedirectStrategy().sendRedirect(request, response, "http://localhost:4200/");

    }

    private Authentication authenticateByUsernameAndPassword(UserPrincipal userPrincipal, String username, String password) {
        User user = userService.findUserByEmail(TenantId.SYS_TENANT_ID, username);
        if (user == null) {
            throw new UsernameNotFoundException("User not found: " + username);
        }

        try {

            UserCredentials userCredentials = userService.findUserCredentialsByUserId(TenantId.SYS_TENANT_ID, user.getId());
            if (userCredentials == null) {
                throw new UsernameNotFoundException("User credentials not found");
            }

            try {
                systemSecurityService.validateUserCredentials(user.getTenantId(), userCredentials, username, password);
            } catch (LockedException e) {
                throw e;
            }

            if (user.getAuthority() == null)
                throw new InsufficientAuthenticationException("User has no authority assigned");

            SecurityUser securityUser = new SecurityUser(user, userCredentials.isEnabled(), userPrincipal);
            return new UsernamePasswordAuthenticationToken(securityUser, null, securityUser.getAuthorities());
        } catch (Exception e) {
            throw e;
        }
    }
}
