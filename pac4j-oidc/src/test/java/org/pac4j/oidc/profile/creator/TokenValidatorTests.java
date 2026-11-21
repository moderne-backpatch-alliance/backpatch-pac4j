package org.pac4j.oidc.profile.creator;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import org.junit.Before;
import org.junit.Test;
import org.pac4j.core.exception.TechnicalException;
import org.pac4j.core.util.TestsConstants;
import org.pac4j.core.util.TestsHelper;
import org.pac4j.oidc.config.OidcConfiguration;

import java.lang.reflect.Field;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;

import static org.mockito.Mockito.*;
import static org.junit.Assert.*;

/**
 * Tests {@link TokenValidator}.
 *
 * @author Jerome LELEU
 * @since 5.2.0
 */
public final class TokenValidatorTests implements TestsConstants {

    private OidcConfiguration configuration;

    private List<JWSAlgorithm> algorithms;

    @Before
    public void setUp() throws URISyntaxException {
        configuration = mock(OidcConfiguration.class);
        final OIDCProviderMetadata metadata = mock(OIDCProviderMetadata.class);
        when(metadata.getIssuer()).thenReturn(new Issuer(PAC4J_URL));
        when(metadata.getJWKSetURI()).thenReturn(new URI(PAC4J_BASE_URL));
        when(configuration.findProviderMetadata()).thenReturn(metadata);
        when(configuration.getClientId()).thenReturn(ID);
        when(configuration.getSecret()).thenReturn(SECRET);
        algorithms = new ArrayList<>();
        when(metadata.getIDTokenJWSAlgs()).thenReturn(algorithms);
    }

    @Test
    public void testNoneAlgoNotAllowed() {
        algorithms.add(JWSAlgorithm.parse("none"));
        TestsHelper.expectException(() -> new TokenValidator(configuration), TechnicalException.class,
            "Unsigned ID tokens are not allowed: they must be explicitly enabled on client side and " +
                "the response_type used must return no ID Token from the authorization endpoint");
    }

    @Test
    public void testNoneAlgoAllowed() throws Exception {
        algorithms.add(JWSAlgorithm.parse("none"));
        when(configuration.isAllowUnsignedIdTokens()).thenReturn(true);
        final TokenValidator validator = new TokenValidator(configuration);
        final List<IDTokenValidator> validators = getIdTokenValidators(validator);
        assertEquals(1, validators.size());
        assertTrue(validators.get(0) instanceof IDTokenValidator);
    }

    @Test
    public void testNoneAlgoAllowedButIdTokenRequested() {
        when(configuration.getResponseType()).thenReturn("code id_token");
        algorithms.add(JWSAlgorithm.parse("none"));
        when(configuration.isAllowUnsignedIdTokens()).thenReturn(true);
        TestsHelper.expectException(() -> new TokenValidator(configuration), TechnicalException.class,
            "Unsigned ID tokens are not allowed: they must be explicitly enabled on client side and " +
                "the response_type used must return no ID Token from the authorization endpoint");
    }

    // this line has no getIdTokenValidators() accessor, so the private field is read directly
    @SuppressWarnings("unchecked")
    private static List<IDTokenValidator> getIdTokenValidators(final TokenValidator validator) throws Exception {
        final Field field = TokenValidator.class.getDeclaredField("idTokenValidators");
        field.setAccessible(true);
        return (List<IDTokenValidator>) field.get(validator);
    }
}
