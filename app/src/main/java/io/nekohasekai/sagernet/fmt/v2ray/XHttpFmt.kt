package io.nekohasekai.sagernet.fmt.v2ray

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import moe.matsuri.nb4a.SingBoxOptions.SingBoxOption
import moe.matsuri.nb4a.utils.listByLineOrComma
import okhttp3.HttpUrl

internal fun StandardV2RayBean.readXHttp(url: HttpUrl) {
    val protection = url.queryParameter("security").orEmpty()
    require(protection in listOf("", "none", "tls", "reality")) { "Неизвестный режим защиты XHTTP" }
    require(protection != "reality" || !realityPubKey.isNullOrBlank()) {
        "В ссылке XHTTP не указан открытый ключ REALITY"
    }
    host = url.queryParameter("host").orEmpty()
    path = url.queryParameter("path") ?: path.orEmpty()
    xhttpMode = url.queryParameter("mode").orEmpty()
    xhttpEncryption = url.queryParameter("encryption").orEmpty().ifBlank { "none" }
    xhttpExtra = url.queryParameter("extra").orEmpty()
    xhttpSpiderX = url.queryParameter("spx").orEmpty()
    xhttpMldsaVerify = url.queryParameter("pqv").orEmpty()
    val extra = parseXHttpExtra(xhttpExtra)
    if (xhttpMode.isBlank()) xhttpMode = extra?.get("mode")?.let {
        require(it.isJsonPrimitive && it.asJsonPrimitive.isString) { "Некорректный режим XHTTP в extra" }
        it.asString
    }.orEmpty()
}

internal fun StandardV2RayBean.writeXHttp(builder: HttpUrl.Builder) {
    val fields = mapOf(
        "host" to host, "path" to path, "mode" to xhttpMode, "extra" to xhttpExtra,
        "spx" to xhttpSpiderX, "pqv" to xhttpMldsaVerify,
    )
    for ((key, value) in fields) {
        if (value.isNotBlank()) builder.addQueryParameter(key, value)
    }
}

internal fun StandardV2RayBean.buildXHttpOutbound(): SingBoxOption {
    require(isVLESS) { "XHTTP поддерживается для VLESS" }
    val protection = when {
        security != "tls" -> "none"
        realityPubKey.isNotBlank() -> "reality"
        else -> "tls"
    }
    return SingBoxOption().apply {
        _hack_config_map.putAll(
            mapOf(
                "type" to "xray-xhttp", "server" to serverAddress, "server_port" to serverPort,
                "uuid" to uuid, "flow" to encryption, "encryption" to xhttpEncryption,
                "host" to host, "path" to path, "mode" to xhttpMode, "security" to protection,
                "server_name" to sni, "alpn" to alpn.listByLineOrComma(),
                "fingerprint" to utlsFingerprint, "public_key" to realityPubKey, "short_id" to realityShortId,
                "spider_x" to xhttpSpiderX, "mldsa65_verify" to xhttpMldsaVerify,
                "allow_insecure" to allowInsecure, "certificate" to certificates, "ech" to enableECH,
            )
        )
        parseXHttpExtra(xhttpExtra)?.let { _hack_config_map["extra"] = it }
    }
}

private fun parseXHttpExtra(raw: String): JsonObject? {
    if (raw.isBlank()) return null
    require(raw.length <= 32768) { "Слишком большой параметр extra в ссылке XHTTP" }
    val element = runCatching { JsonParser.parseString(raw) }.getOrNull()
    require(element != null && element.isJsonObject) { "Параметр extra ссылки XHTTP должен быть объектом JSON" }
    return element.asJsonObject
}
