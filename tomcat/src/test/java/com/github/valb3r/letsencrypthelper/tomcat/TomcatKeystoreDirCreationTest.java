package com.github.valb3r.letsencrypthelper.tomcat;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.web.ServerProperties;

import java.io.File;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class TomcatKeystoreDirCreationTest {

    @Test
    public void createsParentDirWhenAutoCreateEnabled() throws Exception {
        Path tmp = Path.of(System.getProperty("java.io.tmpdir"));
        Path base = tmp.resolve("letsencrypt-helper-test-tomcat").resolve("nested");
        Files.deleteIfExists(base.resolve("keystore.p12"));
        // ensure parent does not exist
        if (Files.exists(base)) {
            Files.walk(base).map(Path::toFile).forEach(File::delete);
        }

        String keystorePath = "file:" + base.resolve("keystore.p12").toAbsolutePath().toString();

        ServerProperties props = new ServerProperties();
        java.lang.reflect.Method setSsl = null;
        for (var m : ServerProperties.class.getMethods()) {
            if (m.getName().equals("setSsl") && m.getParameterCount() == 1) {
                setSsl = m;
                break;
            }
        }
        if (setSsl == null) throw new IllegalStateException("ServerProperties.setSsl method not found");
        Class<?> sslClass = setSsl.getParameterTypes()[0];
        Object ssl = sslClass.getDeclaredConstructor().newInstance();
        var setKeyStore = sslClass.getMethod("setKeyStore", String.class);
        var setKeyStorePassword = sslClass.getMethod("setKeyStorePassword", String.class);
        var setKeyAlias = sslClass.getMethod("setKeyAlias", String.class);
        var setKeyStoreType = sslClass.getMethod("setKeyStoreType", String.class);
        setKeyStore.invoke(ssl, keystorePath);
        setKeyStorePassword.invoke(ssl, "changeit");
        setKeyAlias.invoke(ssl, "alias");
        setKeyStoreType.invoke(ssl, "PKCS12");
        setSsl.invoke(props, ssl);

        var cfg = new TomcatWellKnownLetsEncryptChallengeEndpointConfig(
                props, 443, "example.com", "mailto:test@example.com",
                "acct", "acme://letsencrypt.org", 1024,
                Duration.ofDays(30), Duration.ofMinutes(1), Duration.ofDays(3650), true, true, true, 80, true
        );

        Method m = TomcatWellKnownLetsEncryptChallengeEndpointConfig.class.getDeclaredMethod("createBasicKeystoreIfMissing");
        m.setAccessible(true);

        try {
            m.invoke(cfg);

            assertThat(Files.exists(base)).isTrue();
            assertThat(Files.exists(base.resolve("keystore.p12"))).isTrue();
        } finally {
            // cleanup
            Files.deleteIfExists(base.resolve("keystore.p12"));
            if (Files.exists(base)) {
                Files.deleteIfExists(base);
                Path parent = base.getParent();
                if (parent != null && Files.exists(parent)) {
                    Files.deleteIfExists(parent);
                }
            }
        }
    }

    @Test
    public void failsWhenAutoCreateDisabled() throws Exception {
        Path tmp = Path.of(System.getProperty("java.io.tmpdir"));
        Path base = tmp.resolve("letsencrypt-helper-test-tomcat").resolve("nested-no-create");
        Files.deleteIfExists(base.resolve("keystore.p12"));
        if (Files.exists(base)) {
            Files.walk(base).map(Path::toFile).forEach(File::delete);
        }

        String keystorePath = "file:" + base.resolve("keystore.p12").toAbsolutePath().toString();

        ServerProperties props = new ServerProperties();
        java.lang.reflect.Method setSsl2 = null;
        for (var m : ServerProperties.class.getMethods()) {
            if (m.getName().equals("setSsl") && m.getParameterCount() == 1) {
                setSsl2 = m;
                break;
            }
        }
        if (setSsl2 == null) throw new IllegalStateException("ServerProperties.setSsl method not found");
        Class<?> sslClass2 = setSsl2.getParameterTypes()[0];
        Object ssl2 = sslClass2.getDeclaredConstructor().newInstance();
        var setKeyStore2 = sslClass2.getMethod("setKeyStore", String.class);
        var setKeyStorePassword2 = sslClass2.getMethod("setKeyStorePassword", String.class);
        var setKeyAlias2 = sslClass2.getMethod("setKeyAlias", String.class);
        var setKeyStoreType2 = sslClass2.getMethod("setKeyStoreType", String.class);
        setKeyStore2.invoke(ssl2, keystorePath);
        setKeyStorePassword2.invoke(ssl2, "changeit");
        setKeyAlias2.invoke(ssl2, "alias");
        setKeyStoreType2.invoke(ssl2, "PKCS12");
        setSsl2.invoke(props, ssl2);

        var cfg = new TomcatWellKnownLetsEncryptChallengeEndpointConfig(
                props, 443, "example.com", "mailto:test@example.com",
                "acct", "acme://letsencrypt.org", 1024,
                Duration.ofDays(30), Duration.ofMinutes(1), Duration.ofDays(3650), true, true, true, 80, false
        );

        Method m = TomcatWellKnownLetsEncryptChallengeEndpointConfig.class.getDeclaredMethod("createBasicKeystoreIfMissing");
        m.setAccessible(true);

        assertThatThrownBy(() -> m.invoke(cfg))
                .satisfies(t -> {
                    assertThat(t.getCause()).isInstanceOf(IllegalStateException.class);
                    assertThat(t.getCause().getMessage()).contains("Keystore parent directory does not exist");
                });
    }
}
