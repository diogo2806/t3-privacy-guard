package br.com.privacyguard.runtime.policy;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class ContractTextTest {
    @Test
    void trimFollowsRustWhiteSpaceNotJavaWhitespace() {
        assertThat(ContractText.trim(" 　value ")).isEqualTo("value");
        // Java strips U+001C (information separator) but Rust does not treat it as whitespace.
        assertThat("\u001Cvalue".strip()).isEqualTo("value");
        assertThat(ContractText.trim("\u001Cvalue")).isEqualTo("\u001Cvalue");
    }

    @Test
    void lowercaseOnlyTouchesAscii() {
        assertThat(ContractText.asciiLowercase("ÉTAT-API")).isEqualTo("État-api");
    }

    @Test
    void lengthIsCountedInUtf8Bytes() {
        assertThat(ContractText.utf8Length("abc")).isEqualTo(3);
        assertThat(ContractText.utf8Length("é")).isEqualTo(2);
        assertThat(ContractText.utf8Length("€")).isEqualTo(3);
        assertThat(ContractText.utf8Length("😀")).isEqualTo(4);
    }

    @Test
    void orderingFollowsCodePointsNotUtf16Units() {
        String privateUse = "";
        String emoji = "😀";
        assertThat(privateUse.compareTo(emoji)).isPositive();
        assertThat(ContractText.CODE_POINT_ORDER.compare(privateUse, emoji)).isNegative();
        assertThat(ContractText.CODE_POINT_ORDER.compare("abc", "abcd")).isNegative();
        assertThat(ContractText.CODE_POINT_ORDER.compare("abc", "abc")).isZero();
    }

    @Test
    void detectsUnpairedSurrogates() {
        assertThat(ContractText.hasUnpairedSurrogate("😀")).isFalse();
        assertThat(ContractText.hasUnpairedSurrogate("a\uD83D")).isTrue();
        assertThat(ContractText.hasUnpairedSurrogate("\uDE00a")).isTrue();
    }
}
