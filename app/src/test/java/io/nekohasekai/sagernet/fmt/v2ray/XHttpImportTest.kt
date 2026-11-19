package io.nekohasekai.sagernet.fmt.v2ray

import io.nekohasekai.sagernet.fmt.KryoConverters
import okhttp3.HttpUrl.Companion.toHttpUrl
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class XHttpImportTest {
    @Test
    fun parsesAndRoundTripsLinkFrom3xUi() {
        val extra = """{"mode":"auto","xPaddingBytes":"100-1000","sessionIDPlacement":"query","sessionPlacement":"query"}"""
        val url = "https://00000000-0000-4000-8000-000000000001@edge.example:8443/".toHttpUrl().newBuilder()
            .fragment("Проверка XHTTP")
            .addQueryParameter("type", "xhttp")
            .addQueryParameter("encryption", "none")
            .addQueryParameter("host", "http.example")
            .addQueryParameter("path", "/x http?foo=1&bar=2")
            .addQueryParameter("security", "reality")
            .addQueryParameter("sni", "tls.example")
            .addQueryParameter("fp", "chrome")
            .addQueryParameter("pbk", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            .addQueryParameter("sid", "0123456789abcdef")
            .addQueryParameter("spx", "/test path")
            .addQueryParameter("pqv", "synthetic-value")
            .addQueryParameter("extra", extra)
        val imported = parseV2Ray(url.build().toString().replaceFirst("https://", "vless://"))
        imported.initializeDefaultValues()
        val stored = KryoConverters.serialize(imported)
        val saved = KryoConverters.deserialize(VMessBean(), stored)
        val outbound = buildSingBoxOutboundStandardV2RayBean(saved).asMap()

        assertTrue(saved.isVLESS)
        assertEquals("Проверка XHTTP", saved.name)
        assertEquals("auto", saved.xhttpMode)
        assertEquals(extra, saved.xhttpExtra)
        assertEquals("/test path", saved.xhttpSpiderX)
        assertEquals("synthetic-value", saved.xhttpMldsaVerify)
        assertEquals("xray-xhttp", outbound["type"])
        assertEquals("edge.example", outbound["server"])
        assertEquals("http.example", outbound["host"])
        assertEquals("tls.example", outbound["server_name"])
        assertEquals("/x http?foo=1&bar=2", outbound["path"])
        assertEquals("reality", outbound["security"])
        assertTrue(outbound["extra"] is Map<*, *>)
        val reimported = parseV2Ray(saved.toUriVMessVLESSTrojan(false))
        reimported.initializeDefaultValues()
        assertArrayEquals(stored, KryoConverters.serialize(reimported))
    }

    @Test
    fun acceptsSplithttpAliasAndRetainsVlessFlowForValidation() {
        val bean = parseV2Ray(
            "vless://00000000-0000-4000-8000-000000000001@edge.example:8443?type=splithttp" +
                "&mode=stream-one&encryption=none&flow=xtls-rprx-vision-udp443&security=tls&host=http.example"
        )
        bean.initializeDefaultValues()
        assertEquals("xhttp", bean.type)
        assertEquals("stream-one", bean.xhttpMode)
        assertEquals("xtls-rprx-vision-udp443", bean.encryption)
        assertEquals("", bean.sni)
    }

    @Test
    fun preservesVlessTcpRealityAndVision() {
        val bean = parseV2Ray(
            "vless://00000000-0000-4000-8000-000000000001@edge.example:443?type=tcp" +
                "&flow=xtls-rprx-vision&security=reality&fp=chrome&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=0123"
        )
        bean.initializeDefaultValues()
        val stored = KryoConverters.serialize(bean)
        val saved = KryoConverters.deserialize(VMessBean(), stored)
        assertArrayEquals(stored, KryoConverters.serialize(saved))
        assertEquals("tcp", saved.type)
        assertEquals("xtls-rprx-vision", saved.encryption)
        assertEquals("0123", saved.realityShortId)
        assertEquals("chrome", saved.utlsFingerprint)
        val exported = saved.toUriVMessVLESSTrojan(false).replaceFirst("vless://", "https://").toHttpUrl()
        assertEquals("reality", exported.queryParameter("security"))
        assertEquals("xtls-rprx-vision", exported.queryParameter("flow"))
    }
}
