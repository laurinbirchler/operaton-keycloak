package org.operaton.bpm.extension.keycloak.showcase.rest;

import org.operaton.bpm.engine.IdentityService;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;

/**
 * Optional Security Configuration for Operaton REST Api.
 */
@Configuration
@ConditionalOnProperty(name = "rest.security.enabled", havingValue = "true", matchIfMissing = true)
public class RestApiSecurityConfig {

  private static final String OAUTH2_PROVIDER_PROPERTY_PREFIX = "spring.security.oauth2.client.provider.";

  /**
   * Configuration for REST Api security.
   */
  private final RestApiSecurityConfigurationProperties configProps;

  /**
   * Access to Operaton's Identity Service.
   */
  private final IdentityService identityService;

  /**
   * Access to Spring Security OAuth2 client service.
   */
  private final OAuth2AuthorizedClientService clientService;

  private final ApplicationContext applicationContext;

  public RestApiSecurityConfig(RestApiSecurityConfigurationProperties configProps, IdentityService identityService,
      OAuth2AuthorizedClientService clientService, ApplicationContext applicationContext) {
    this.configProps = configProps;
    this.identityService = identityService;
    this.clientService = clientService;
    this.applicationContext = applicationContext;
  }

  /**
   * {@inheritDoc}
   */
  @Bean
  @Order(1)
  public SecurityFilterChain httpSecurityRest(HttpSecurity http, JwtDecoder jwtDecoder) {
    String jwkSetUri = applicationContext.getEnvironment()
        .getRequiredProperty(OAUTH2_PROVIDER_PROPERTY_PREFIX + configProps.getProvider() + ".jwk-set-uri");
    PathPatternRequestMatcher.Builder pathPattern = PathPatternRequestMatcher.withDefaults();

    // No explicit CSRF override needed: the OAuth2 resource server configurer already exempts
    // bearer-token requests from CSRF protection, and this chain only accepts bearer tokens.
    return http.securityMatcher(pathPattern.matcher("/engine-rest/**"))
        .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
        .oauth2ResourceServer(
            oauth2ResourceServer -> oauth2ResourceServer.jwt(jwt -> jwt.decoder(jwtDecoder).jwkSetUri(jwkSetUri)))
        .addFilterBefore(keycloakAuthenticationFilter(), AuthorizationFilter.class)
        .build();
  }

  /**
   * Create a JWT decoder with issuer and audience claim validation.
   *
   * @return the JWT decoder
   */
  @Bean
  public JwtDecoder jwtDecoder() {
    String issuerUri = applicationContext.getEnvironment()
        .getRequiredProperty(OAUTH2_PROVIDER_PROPERTY_PREFIX + configProps.getProvider() + ".issuer-uri");

    NimbusJwtDecoder jwtDecoder = JwtDecoders.fromOidcIssuerLocation(issuerUri);

    OAuth2TokenValidator<Jwt> audienceValidator = new AudienceValidator(configProps.getRequiredAudience());
    OAuth2TokenValidator<Jwt> withIssuer = JwtValidators.createDefaultWithIssuer(issuerUri);
    OAuth2TokenValidator<Jwt> withAudience = new DelegatingOAuth2TokenValidator<>(withIssuer, audienceValidator);

    jwtDecoder.setJwtValidator(withAudience);

    return jwtDecoder;
  }

  /**
   * Creates the REST Api Keycloak Authentication Filter.
   *
   * @return the filter
   */
  @SuppressWarnings({ "unchecked", "rawtypes" })
  public KeycloakAuthenticationFilter keycloakAuthenticationFilter() {
    String userNameAttribute = this.applicationContext.getEnvironment()
        .getRequiredProperty(
            OAUTH2_PROVIDER_PROPERTY_PREFIX + this.configProps.getProvider() + ".user-name-attribute");

    return new KeycloakAuthenticationFilter(this.identityService, this.clientService, userNameAttribute);
  }

}
