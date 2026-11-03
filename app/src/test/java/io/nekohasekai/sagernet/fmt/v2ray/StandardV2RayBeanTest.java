package io.nekohasekai.sagernet.fmt.v2ray;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;

import com.esotericsoftware.kryo.io.ByteBufferInput;
import com.esotericsoftware.kryo.io.ByteBufferOutput;

import org.junit.Test;

import java.util.List;
import java.util.Random;
import java.util.function.Supplier;

import io.nekohasekai.sagernet.fmt.KryoConverters;
import io.nekohasekai.sagernet.fmt.http.HttpBean;
import io.nekohasekai.sagernet.fmt.shadowsocks.ShadowsocksBean;
import io.nekohasekai.sagernet.fmt.socks.SOCKSBean;
import io.nekohasekai.sagernet.fmt.trojan.TrojanBean;

public class StandardV2RayBeanTest {

    private static final List<Supplier<StandardV2RayBean>> TYPES = List.of(
            VLESSBean::new, VMessBean::new, TrojanBean::new,
            HttpBean::new, SOCKSBean::new, ShadowsocksBean::new);

    private static StandardV2RayBean profile(Supplier<StandardV2RayBean> factory, String security) {
        StandardV2RayBean bean = factory.get();
        bean.initializeDefaultValues();
        bean.serverAddress = "proxy.example";
        bean.serverPort = 8080;
        bean.name = "Profile — тест";
        bean.uuid = "12345678-1234-1234-1234-123456789abc";
        bean.type = "ws";
        bean.host = "backend.example";
        bean.path = "/socket";
        bean.maxEarlyData = 2048;
        bean.earlyDataHeaderName = "Sec-WebSocket-Protocol";
        bean.security = security;
        bean.sni = "tls"; // Valid single-label name: do not guess the format from strings.
        bean.alpn = "http/1.1";
        bean.realityPublicKey = "test-public-key";
        bean.realityShortId = "0123456789abcdef";
        bean.packetEncoding = "xudp";
        bean.muxConcurrency = 13;
        bean.echQueryName = "ech.example";
        if (bean instanceof VLESSBean vless) vless.flow = "xtls-rprx-vision";
        if (bean instanceof VMessBean vmess) vmess.alterId = 7;
        if (bean instanceof TrojanBean trojan) trojan.password = "synthetic-test-password";
        if (bean instanceof HttpBean http) http.password = "synthetic-http-password";
        if (bean instanceof SOCKSBean socks) socks.password = "synthetic-socks-password";
        if (bean instanceof ShadowsocksBean ss) ss.password = "synthetic-ss-password";
        return bean;
    }

    // Independent writer for the released v39/upstream-v40/fronting-v40 layouts.
    // Do not generate these fixtures with the current serializer: that would hide migrations.
    private static byte[] legacy(StandardV2RayBean bean, int version, boolean fronting) {
        ByteBufferOutput out = new ByteBufferOutput(512, -1);
        int httpVersion = version == 40 && !fronting ? 5 : 3;
        if (bean instanceof TrojanBean) out.writeInt(2);
        if (bean instanceof SOCKSBean) out.writeInt(4);
        if (bean instanceof ShadowsocksBean) out.writeInt(6);
        if (bean instanceof HttpBean) out.writeInt(httpVersion);
        out.writeInt(version);
        out.writeString(bean.serverAddress);
        out.writeInt(bean.serverPort);
        out.writeString(bean.uuid);
        out.writeString(bean.encryption);
        out.writeString(bean.type);
        switch (bean.type) {
            case "ws" -> {
                out.writeString(bean.host);
                out.writeString(bean.path);
                out.writeInt(bean.maxEarlyData);
                out.writeBoolean(bean.wsUseBrowserForwarder);
                out.writeString(bean.earlyDataHeaderName);
                if (fronting) out.writeString(bean.frontingHost);
            }
            case "quic" -> {
                out.writeString(bean.headerType);
                out.writeString(bean.quicSecurity);
                out.writeString(bean.quicKey);
            }
            default -> throw new AssertionError("Unsupported test transport");
        }
        out.writeString(bean.security);
        switch (bean.security) {
            case "tls" -> {
                out.writeString(bean.sni);
                out.writeString(bean.alpn);
                out.writeString(bean.certificates);
                out.writeString(bean.pinnedPeerCertificateChainSha256);
                out.writeString(bean.pinnedPeerCertificatePublicKeySha256);
                out.writeString(bean.pinnedPeerCertificateSha256);
                out.writeBoolean(bean.allowInsecure);
                out.writeString(bean.utlsFingerprint);
                out.writeString(bean.echConfigList);
                out.writeString(bean.mtlsCertificate);
                out.writeString(bean.mtlsCertificatePrivateKey);
            }
            case "reality" -> {
                out.writeString(bean.sni);
                out.writeString(bean.realityPublicKey);
                out.writeString(bean.realityShortId);
                out.writeString(bean.realityFingerprint);
                out.writeBoolean(bean.realityDisableX25519Mlkem768);
            }
        }
        if (bean instanceof VMessBean vmess) {
            out.writeInt(vmess.alterId);
            out.writeBoolean(vmess.experimentalAuthenticatedLength);
            out.writeBoolean(vmess.experimentalNoTerminationSignal);
        }
        if (bean instanceof VLESSBean vless) out.writeString(vless.flow);
        out.writeString(bean.packetEncoding);
        out.writeBoolean(bean.mux);
        out.writeInt(bean.muxConcurrency);
        out.writeString(bean.muxPacketEncoding);
        if (bean instanceof ShadowsocksBean ss) out.writeBoolean(ss.singUoT);
        if (bean instanceof SOCKSBean socks) out.writeBoolean(socks.singUoT);
        out.writeBoolean(bean.singMux);
        out.writeString(bean.singMuxProtocol);
        out.writeInt(bean.singMuxMaxConnections);
        out.writeInt(bean.singMuxMinStreams);
        out.writeInt(bean.singMuxMaxStreams);
        out.writeBoolean(bean.singMuxPadding);
        out.writeBoolean(bean.echEnabled);
        out.writeString(bean.realityMldsa65Verify);
        out.writeString(bean.serverNameToVerify);
        out.writeBoolean(bean.hy2ChromeParrot);
        out.writeString(bean.echQueryName);
        if (bean instanceof TrojanBean trojan) out.writeString(trojan.password);
        if (bean instanceof HttpBean http) {
            out.writeString(http.username);
            out.writeString(http.password);
            out.writeBoolean(false); // v3: retired trustTunnelUot; v5: connectUDP.
            if (httpVersion >= 5) out.writeString(http.uriTemplate);
        }
        if (bean instanceof SOCKSBean socks) {
            out.writeInt(socks.protocol);
            out.writeString(socks.username);
            out.writeString(socks.password);
            out.writeBoolean(socks.singUoT);
        }
        if (bean instanceof ShadowsocksBean ss) {
            out.writeString(ss.method);
            out.writeString(ss.password);
            out.writeString(ss.plugin);
            out.writeBoolean(ss.experimentReducedIvHeadEntropy);
            out.writeBoolean(ss.singUoT);
        }
        out.writeInt(2); // AbstractBean's extra metadata.
        out.writeString(bean.name);
        out.writeInt(bean.extraType);
        return out.toBytes();
    }

    private static void assertProfile(StandardV2RayBean expected, StandardV2RayBean actual) {
        assertEquals(expected.serverAddress, actual.serverAddress);
        assertEquals(expected.serverPort, actual.serverPort);
        assertEquals(expected.name, actual.name);
        assertEquals(expected.type, actual.type);
        assertEquals(expected.host, actual.host);
        assertEquals(expected.path, actual.path);
        assertEquals(expected.frontingHost, actual.frontingHost);
        assertEquals(expected.security, actual.security);
        assertEquals(expected.packetEncoding, actual.packetEncoding);
        assertEquals(expected.muxConcurrency, actual.muxConcurrency);
        assertEquals(expected.echQueryName, actual.echQueryName);
        if (expected.security.equals("tls") || expected.security.equals("reality")) {
            assertEquals(expected.sni, actual.sni);
        }
        if (expected.security.equals("tls")) {
            assertEquals(expected.alpn, actual.alpn);
            assertEquals(expected.certificates, actual.certificates);
        }
        if (expected instanceof VLESSBean vless) assertEquals(vless.flow, ((VLESSBean) actual).flow);
        if (expected instanceof VMessBean vmess) assertEquals(vmess.alterId, ((VMessBean) actual).alterId);
        if (expected instanceof TrojanBean trojan) assertEquals(trojan.password, ((TrojanBean) actual).password);
        assertArrayEquals(KryoConverters.serialize(expected), KryoConverters.serialize(actual));
    }

    @Test
    public void readsOriginalProfilesBeforeAndAfterVersion40() {
        for (var factory : TYPES) {
            for (String security : List.of("none", "tls", "reality")) {
                for (int version : List.of(39, 40)) {
                    var expected = profile(factory, security);
                    assertProfile(expected, KryoConverters.deserialize(factory.get(), legacy(expected, version, false)));
                }
            }
        }
    }

    @Test
    public void readsReleasedFrontingProfilesIncludingAmbiguousHostNames() {
        for (var factory : TYPES) {
            for (String security : List.of("none", "tls", "reality")) {
                for (String host : List.of("", "front.example", "none", "tls", "reality")) {
                    var expected = profile(factory, security);
                    expected.frontingHost = host;
                    assertProfile(expected, KryoConverters.deserialize(factory.get(), legacy(expected, 40, true)));
                }
            }
        }
    }

    @Test
    public void readsLargeOriginalProfilesWithoutLeavingFailedAttemptState() {
        var expected = profile(VLESSBean::new, "tls");
        expected.certificates = "synthetic-certificate\n".repeat(4096);
        assertProfile(expected, KryoConverters.deserialize(new VLESSBean(), legacy(expected, 40, false)));
    }

    @Test
    public void randomizedLegacyProfilesRemainEquivalent() {
        String[] words = {"", "none", "tls", "reality", "front.example",
                "xn--e1afmkfd.xn--p1ai", "test-".repeat(300)};
        String[] securities = {"none", "tls", "reality"};
        Random random = new Random(662);
        for (int i = 0; i < 15000; i++) {
            var factory = TYPES.get(random.nextInt(TYPES.size()));
            var expected = profile(factory, securities[random.nextInt(securities.length)]);
            boolean fronting = random.nextBoolean();
            if (fronting) expected.frontingHost = words[random.nextInt(words.length)];
            expected.sni = words[random.nextInt(words.length)];
            expected.certificates = words[random.nextInt(words.length)];
            expected.mux = random.nextBoolean();
            expected.muxConcurrency = random.nextInt(1024);
            expected.maxEarlyData = random.nextInt(4096);
            expected.singMux = random.nextBoolean();
            expected.singMuxMaxConnections = random.nextInt(256);
            expected.singMuxMinStreams = random.nextInt(256);
            expected.singMuxMaxStreams = random.nextInt(256);
            expected.singMuxPadding = random.nextBoolean();
            expected.echEnabled = random.nextBoolean();
            if (expected instanceof VLESSBean bean) bean.flow = random.nextBoolean() ? "" : "xtls-rprx-vision";
            if (expected instanceof VMessBean bean) bean.alterId = random.nextInt(64);
            var actual = KryoConverters.deserialize(factory.get(), legacy(expected, 40, fronting));
            assertArrayEquals("Synthetic migration case " + i,
                    KryoConverters.serialize(expected), KryoConverters.serialize(actual));
        }
    }

    @Test
    public void newProfilesUseADistinctForkVersionAndRoundTrip() {
        for (var factory : TYPES) {
            var expected = profile(factory, "none");
            expected.frontingHost = "front.example";
            byte[] bytes = KryoConverters.serialize(expected);
            ByteBufferInput input = new ByteBufferInput(bytes);
            if (!(expected instanceof VLESSBean) && !(expected instanceof VMessBean)) input.readInt();
            assertTrue("The fork must not reuse upstream's version namespace", input.readInt() > 0xffff);
            assertProfile(expected, KryoConverters.deserialize(factory.get(), bytes));
        }
    }

    @Test
    public void retainsOldQuicAlpnDefaults() {
        var expected = profile(VLESSBean::new, "tls");
        expected.type = "quic";
        expected.alpn = "";
        var actual = KryoConverters.deserialize(new VLESSBean(), legacy(expected, 39, false));
        assertEquals("h2\nhttp/1.1", actual.alpn);
    }
}
