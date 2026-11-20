/** Medición reproducible del híbrido de la app y de las primitivas asimétricas aisladas. */
package com.example.securesms

import com.example.securesms.crypto.Algorithm
import com.example.securesms.crypto.CryptoContext
import com.example.securesms.crypto.CryptoEngine
import com.example.securesms.crypto.CryptoResult
import com.example.securesms.crypto.EmilioEccEngine
import com.example.securesms.crypto.EmilioRsaEngine
import com.example.securesms.crypto.KeyProfile
import com.example.securesms.crypto.Suite
import com.example.securesms.crypto.fingerprint
import com.example.securesms.protocol.Envelope
import com.example.securesms.protocol.SmsProtocol
import kotlinx.coroutines.runBlocking
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Security
import java.security.spec.ECGenParameterSpec
import java.security.spec.MGF1ParameterSpec
import java.time.OffsetDateTime
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import kotlin.math.log10
import kotlin.math.pow
import kotlin.math.sqrt

class HybridBenchmarkTest {
    @Test
    fun recordsThirtyRepetitionsOfHybridAndIsolatedOperations() {
        val enabled = System.getenv("SECURESMS_BENCHMARK") == "1" ||
            System.getProperty("securesms.benchmark") == "1"
        assumeTrue(enabled)
        if (Security.getProvider("BC") == null) Security.addProvider(BouncyCastleProvider())
        val samples = mutableListOf<Sample>()
        runBlocking { measureHybrid(samples) }
        measureIsolated(samples)
        val results = resultsDirectory()
        writeRaw(File(results, "measurements.csv"), samples)
        val summary = summarize(samples)
        writeSummary(File(results, "summary.csv"), summary)
        writeMetadata(File(results, "run-metadata.txt"))
        writeCharts(results, summary)
        assertTrue(samples.count { it.block == "hybrid" && it.operation == "encrypt" } >= 30 * 4 * 4)
    }

    private suspend fun measureHybrid(samples: MutableList<Sample>) {
        val messages = listOf(
            ByteArray(0),
            "hello".encodeToByteArray(),
            ByteArray(200) { 'M'.code.toByte() },
            ByteArray(1024) { 'X'.code.toByte() }
        )
        for (profile in KeyProfile.entries) {
            println("hybrid ${profile.label}")
            val vault = TestVault()
            val engine = engineFor(profile, vault)
            repeat(WARMUP) { engine.generate(profile, "warm-key-$it").ok() }
            repeat(REPETITIONS) { index ->
                val timed = engine.generate(profile, "key-$profile-$index").ok()
                samples += Sample("hybrid", "app", profile.label, "keygen", "", index + 1, timed.elapsedNanos, "", "")
            }
            val identity = engine.generate(profile, "recipient").ok().value
            val context = CryptoContext(
                UUID.randomUUID(), Suite.HYBRID_V1, profile, fingerprint(identity.publicKey)
            )
            for (plaintext in messages) {
                repeat(WARMUP) {
                    val cipher = engine.encrypt(context, identity.publicKey, plaintext).ok()
                    engine.decrypt(context, identity.alias, cipher.value).ok()
                }
                repeat(REPETITIONS) { index ->
                    val encrypted = engine.encrypt(context, identity.publicKey, plaintext).ok()
                    val envelope = Envelope(context, encrypted.value)
                    val encoded = SmsProtocol.encode(envelope)
                    val segments = SmsProtocol.segment(envelope).size
                    samples += Sample(
                        "hybrid", "app", profile.label, "encrypt", plaintext.size.toString(),
                        index + 1, encrypted.elapsedNanos, encoded.size.toString(), segments.toString()
                    )
                    val decrypted = engine.decrypt(context, identity.alias, encrypted.value).ok()
                    assertArrayEquals(plaintext, decrypted.value)
                    samples += Sample(
                        "hybrid", "app", profile.label, "decrypt", plaintext.size.toString(),
                        index + 1, decrypted.elapsedNanos, "", ""
                    )
                }
            }
        }
    }

    private fun measureIsolated(samples: MutableList<Sample>) {
        val payload = ByteArray(32) { it.toByte() }
        for (spec in isolatedSpecs) {
            println("isolated ${spec.profile}")
            repeat(WARMUP) { spec.generate() }
            repeat(REPETITIONS) { index ->
                val started = System.nanoTime()
                spec.generate()
                samples += Sample(
                    "isolated", spec.pair, spec.profile, "keygen", "",
                    index + 1, System.nanoTime() - started, "", ""
                )
            }
            val recipient = spec.generate()
            repeat(WARMUP) { spec.exchange(recipient, payload) }
            repeat(REPETITIONS) { index ->
                val (encryptNs, decryptNs) = spec.exchange(recipient, payload)
                val size = if (spec.rsaBits != null) payload.size.toString() else ""
                samples += Sample(
                    "isolated", spec.pair, spec.profile, "encrypt", size,
                    index + 1, encryptNs, "", ""
                )
                samples += Sample(
                    "isolated", spec.pair, spec.profile, "decrypt", size,
                    index + 1, decryptNs, "", ""
                )
            }
        }
    }

    private fun writeCharts(results: File, summary: List<Summary>) {
        val profiles = KeyProfile.entries.map { it.label }
        val sizes = listOf("0", "5", "200", "1024")
        writeGroupedBars(
            File(results, "hybrid-encrypt.svg"),
            "Hybrid encryption, median of 30 runs",
            "Median time (ms)",
            profiles,
            sizes.map { size -> size to profiles.map { medianMs(summary, "hybrid", it, "encrypt", size) } },
            logarithmic = false
        )
        writeGroupedBars(
            File(results, "hybrid-decrypt.svg"),
            "Hybrid decryption, median of 30 runs",
            "Median time (ms)",
            profiles,
            sizes.map { size -> size to profiles.map { medianMs(summary, "hybrid", it, "decrypt", size) } },
            logarithmic = false
        )
        writeGroupedBars(
            File(results, "hybrid-keygen.svg"),
            "Hybrid key generation, median of 30 runs",
            "Median time (ms)",
            profiles,
            listOf("keygen" to profiles.map { medianMs(summary, "hybrid", it, "keygen", "") }),
            logarithmic = false
        )
        writeGroupedBars(
            File(results, "hybrid-envelope.svg"),
            "Hybrid envelope size",
            "Median envelope (bytes)",
            profiles,
            sizes.map { size ->
                size to profiles.map { summaryValue(summary, "hybrid", it, "encrypt", size) { row -> row.medianEnvelope } }
            },
            logarithmic = false
        )
        writeGroupedBars(
            File(results, "hybrid-segments.svg"),
            "SMS segments for the hybrid envelope",
            "Median segment count",
            profiles,
            sizes.map { size ->
                size to profiles.map { summaryValue(summary, "hybrid", it, "encrypt", size) { row -> row.medianSegments } }
            },
            logarithmic = false
        )
        val isolatedProfiles = isolatedSpecs.map { it.profile }
        writeGroupedBars(
            File(results, "isolated-keygen.svg"),
            "Isolated key generation, median of 30 runs",
            "Median time (ms, logarithmic scale)",
            isolatedProfiles,
            listOf("keygen" to isolatedProfiles.map { medianMs(summary, "isolated", it, "keygen", "") }),
            logarithmic = true
        )
        writeGroupedBars(
            File(results, "isolated-operations.svg"),
            "Isolated asymmetric operations, median of 30 runs",
            "Median time (ms, logarithmic scale)",
            isolatedProfiles,
            listOf("encrypt", "decrypt").map { operation ->
                operation to isolatedProfiles.map { profile ->
                    val size = if (profile.startsWith("RSA")) "32" else ""
                    medianMs(summary, "isolated", profile, operation, size)
                }
            },
            logarithmic = true
        )
    }

    private fun medianMs(summary: List<Summary>, block: String, profile: String, operation: String, bytes: String) =
        summaryValue(summary, block, profile, operation, bytes) { it.medianNs / 1_000_000.0 }

    private fun summaryValue(
        summary: List<Summary>,
        block: String,
        profile: String,
        operation: String,
        bytes: String,
        select: (Summary) -> Double
    ): Double = select(summary.single {
        it.block == block && it.profile == profile && it.operation == operation && it.plaintextBytes == bytes
    })
}

private const val REPETITIONS = 30
private const val WARMUP = 2
private const val PROVIDER = "BC"

private data class Sample(
    val block: String,
    val pair: String,
    val profile: String,
    val operation: String,
    val plaintextBytes: String,
    val repetition: Int,
    val elapsedNs: Long,
    val envelopeBytes: String,
    val smsSegments: String
)

private data class Summary(
    val block: String,
    val pair: String,
    val profile: String,
    val operation: String,
    val plaintextBytes: String,
    val count: Int,
    val medianNs: Double,
    val meanNs: Double,
    val stdevNs: Double,
    val medianEnvelope: Double,
    val medianSegments: Double
)

private class IsolatedSpec(
    val pair: String,
    val profile: String,
    val rsaBits: Int?,
    val curve: String?
) {
    fun generate(): KeyPair = when {
        rsaBits != null -> KeyPairGenerator.getInstance("RSA", PROVIDER).apply { initialize(rsaBits) }.generateKeyPair()
        else -> KeyPairGenerator.getInstance("EC", PROVIDER).apply {
            initialize(ECGenParameterSpec(requireNotNull(curve)))
        }.generateKeyPair()
    }

    /** Devuelve el tiempo de la operación pública y el de la operación privada, sin AES-GCM. */
    fun exchange(recipient: KeyPair, payload: ByteArray): Pair<Long, Long> = if (rsaBits != null) {
        val encryptStarted = System.nanoTime()
        val wrapper = Cipher.getInstance("RSA/ECB/OAEPPadding", PROVIDER)
        wrapper.init(Cipher.ENCRYPT_MODE, recipient.public, isolatedOaep)
        val wrapped = wrapper.doFinal(payload)
        val encryptNs = System.nanoTime() - encryptStarted
        val decryptStarted = System.nanoTime()
        val opener = Cipher.getInstance("RSA/ECB/OAEPPadding", PROVIDER)
        opener.init(Cipher.DECRYPT_MODE, recipient.private, isolatedOaep)
        val opened = opener.doFinal(wrapped)
        val decryptNs = System.nanoTime() - decryptStarted
        check(opened.contentEquals(payload))
        encryptNs to decryptNs
    } else {
        val ephemeral = generate()
        val encryptStarted = System.nanoTime()
        agree(ephemeral.private, recipient.public)
        val encryptNs = System.nanoTime() - encryptStarted
        val decryptStarted = System.nanoTime()
        agree(recipient.private, ephemeral.public)
        val decryptNs = System.nanoTime() - decryptStarted
        encryptNs to decryptNs
    }

    private fun agree(privateKey: PrivateKey, peer: PublicKey) {
        val agreement = KeyAgreement.getInstance("ECDH", PROVIDER)
        agreement.init(privateKey)
        agreement.doPhase(peer, true)
        check(agreement.generateSecret().isNotEmpty())
    }
}

private val isolatedOaep = OAEPParameterSpec(
    "SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT
)

private val isolatedSpecs = listOf(
    IsolatedSpec("rsa2048-p224", "RSA-2048", 2048, null),
    IsolatedSpec("rsa2048-p224", "P-224", null, "secp224r1"),
    IsolatedSpec("rsa3072-p256", "RSA-3072", 3072, null),
    IsolatedSpec("rsa3072-p256", "P-256", null, "secp256r1"),
    IsolatedSpec("rsa7680-p384", "RSA-7680", 7680, null),
    IsolatedSpec("rsa7680-p384", "P-384", null, "secp384r1")
)

private fun engineFor(profile: KeyProfile, vault: TestVault): CryptoEngine = when (profile.algorithm) {
    Algorithm.RSA -> EmilioRsaEngine(vault, setOf(profile))
    Algorithm.ECC -> EmilioEccEngine(vault, setOf(profile))
}

private fun <T> CryptoResult<T>.ok(): CryptoResult.Ok<T> {
    check(this is CryptoResult.Ok) { toString() }
    return this
}

private fun resultsDirectory(): File {
        var dir = File(requireNotNull(System.getProperty("user.dir"))).absoluteFile
    repeat(8) {
        val marker = File(dir, "crypto-benchmark")
        if (marker.isDirectory) return File(marker, "results").apply { mkdirs() }
        dir = dir.parentFile ?: return@repeat
    }
    error("crypto-benchmark directory not found from ${System.getProperty("user.dir")}")
}

private fun writeRaw(file: File, samples: List<Sample>) {
    file.writeText(buildString {
        appendLine("block,pair,profile,operation,plaintext_bytes,repetition,elapsed_ns,envelope_bytes,sms_segments")
        samples.forEach {
            appendLine(
                "${it.block},${it.pair},${it.profile},${it.operation},${it.plaintextBytes}," +
                    "${it.repetition},${it.elapsedNs},${it.envelopeBytes},${it.smsSegments}"
            )
        }
    })
}

private fun summarize(samples: List<Sample>): List<Summary> = samples.groupBy {
    listOf(it.block, it.pair, it.profile, it.operation, it.plaintextBytes)
}.values.map { group ->
    val times = group.map { it.elapsedNs }
    val mean = times.sumOf { it.toDouble() } / times.size
    val first = group.first()
    Summary(
        first.block, first.pair, first.profile, first.operation, first.plaintextBytes, times.size,
        median(times), mean, sampleStdev(times, mean),
        median(group.mapNotNull { it.envelopeBytes.toLongOrNull() }),
        median(group.mapNotNull { it.smsSegments.toLongOrNull() })
    )
}.sortedWith(compareBy({ it.block }, { it.pair }, { it.profile }, { it.operation }, { it.plaintextBytes }))

private fun writeSummary(file: File, rows: List<Summary>) {
    file.writeText(buildString {
        appendLine(
            "block,pair,profile,operation,plaintext_bytes,n,median_ns,mean_ns,stdev_ns," +
                "median_envelope_bytes,median_sms_segments"
        )
        rows.forEach {
            val recorded = it.block == "hybrid" && it.operation == "encrypt"
            val envelope = if (recorded) it.medianEnvelope.toString() else ""
            val segments = if (recorded) it.medianSegments.toString() else ""
            appendLine(
                "${it.block},${it.pair},${it.profile},${it.operation},${it.plaintextBytes},${it.count}," +
                    "${it.medianNs},${it.meanNs},${it.stdevNs},$envelope,$segments"
            )
        }
    })
}

private fun writeMetadata(file: File) {
    val cpu = File("/proc/cpuinfo").useLines { lines ->
        lines.firstOrNull { it.startsWith("model name") }?.substringAfter(":")?.trim()
    } ?: "unavailable"
    file.writeText(
        """
        date=${OffsetDateTime.now()}
        os=${System.getProperty("os.name")} ${System.getProperty("os.version")} ${System.getProperty("os.arch")}
        jvm=${System.getProperty("java.vendor")} ${System.getProperty("java.version")}
        processors=${Runtime.getRuntime().availableProcessors()}
        cpu=$cpu
        repetitions=$REPETITIONS
        warmup_discarded=$WARMUP
        dispersion=sample standard deviation (n-1)
        hybrid_provider=platform JCA through EmilioRsaEngine and EmilioEccEngine, keys in memory
        hybrid_scope=key generation, AES-256-GCM plus RSA-OAEP or ECDH-HKDF, envelope bytes, SMS segments
        isolated_provider=BouncyCastle 1.78.1
        isolated_scope=key generation; RSA-OAEP of a 32-byte key; one ECDH on each side; no AES-GCM
        keystore=not used; these figures are not Android Keystore timings
        """.trimIndent() + "\n"
    )
}

private fun median(values: List<Long>): Double {
    if (values.isEmpty()) return 0.0
    val sorted = values.sorted()
    val mid = sorted.size / 2
    return if (sorted.size % 2 == 0) (sorted[mid - 1] + sorted[mid]) / 2.0 else sorted[mid].toDouble()
}

private fun sampleStdev(values: List<Long>, mean: Double): Double {
    if (values.size < 2) return 0.0
    val sum = values.sumOf { val delta = it - mean; delta * delta }
    return sqrt(sum / (values.size - 1))
}

private fun writeGroupedBars(
    file: File,
    title: String,
    yLabel: String,
    categories: List<String>,
    series: List<Pair<String, List<Double>>>,
    logarithmic: Boolean
) {
    val width = 960.0
    val height = 560.0
    val left = 88.0
    val right = 24.0
    val top = 56.0
    val bottom = 132.0
    val plotWidth = width - left - right
    val plotHeight = height - top - bottom
    val flat = series.flatMap { it.second }.filter { it > 0.0 }
    val maxValue = (flat.maxOrNull() ?: 1.0) * 1.08
    val minLog = log10((flat.minOrNull() ?: 1.0).coerceAtLeast(1e-3))
    val maxLog = log10(maxValue.coerceAtLeast(1e-3))
    fun yOf(value: Double): Double {
        val fraction = if (!logarithmic) {
            value / maxValue
        } else {
            (log10(value.coerceAtLeast(1e-3)) - minLog) / (maxLog - minLog).coerceAtLeast(1e-9)
        }
        return top + plotHeight - fraction.coerceIn(0.0, 1.0) * plotHeight
    }
    val colors = listOf("#1b4f72", "#148f77", "#b9770e", "#6c3483")
    val groupWidth = plotWidth / categories.size
    val barWidth = groupWidth / (series.size + 1)
    val ticks = (0..4).map { step ->
        if (!logarithmic) maxValue * step / 4.0 else 10.0.pow(minLog + (maxLog - minLog) * step / 4.0)
    }
    val svg = buildString {
        appendLine("""<svg xmlns="http://www.w3.org/2000/svg" width="${width.toInt()}" height="${height.toInt()}" viewBox="0 0 $width $height">""")
        appendLine("""<rect width="100%" height="100%" fill="#ffffff"/>""")
        appendLine("""<text x="${width / 2}" y="32" text-anchor="middle" font-family="sans-serif" font-size="18">$title</text>""")
        appendLine("""<text x="18" y="${top + plotHeight / 2}" text-anchor="middle" transform="rotate(-90 18 ${top + plotHeight / 2})" font-family="sans-serif" font-size="13">$yLabel</text>""")
        appendLine("""<line x1="$left" y1="$top" x2="$left" y2="${top + plotHeight}" stroke="#222" stroke-width="1"/>""")
        appendLine("""<line x1="$left" y1="${top + plotHeight}" x2="${left + plotWidth}" y2="${top + plotHeight}" stroke="#222" stroke-width="1"/>""")
        ticks.forEach { tick ->
            val y = yOf(tick)
            appendLine("""<line x1="$left" y1="$y" x2="${left + plotWidth}" y2="$y" stroke="#dddddd"/>""")
            appendLine("""<text x="${left - 8}" y="${y + 4}" text-anchor="end" font-family="sans-serif" font-size="11">${formatTick(tick)}</text>""")
        }
        categories.forEachIndexed { categoryIndex, category ->
            val groupX = left + categoryIndex * groupWidth
            appendLine("""<text x="${groupX + groupWidth / 2}" y="${top + plotHeight + 22}" text-anchor="middle" font-family="sans-serif" font-size="12">$category</text>""")
            series.forEachIndexed { seriesIndex, (_, values) ->
                val value = values[categoryIndex]
                val x = groupX + barWidth * 0.5 + seriesIndex * barWidth
                val y = yOf(value)
                val barHeight = (top + plotHeight - y).coerceAtLeast(0.0)
                appendLine("""<rect x="$x" y="$y" width="${barWidth * 0.8}" height="$barHeight" fill="${colors[seriesIndex % colors.size]}"/>""")
            }
        }
        series.forEachIndexed { index, (name, _) ->
            val x = left + index * 150
            val y = height - 36
            appendLine("""<rect x="$x" y="$y" width="14" height="14" fill="${colors[index % colors.size]}"/>""")
            appendLine("""<text x="${x + 20}" y="${y + 12}" font-family="sans-serif" font-size="12">$name bytes</text>""".replace("keygen bytes", "keygen").replace("encrypt bytes", "encrypt").replace("decrypt bytes", "decrypt"))
        }
        appendLine("</svg>")
    }
    file.writeText(svg)
}

private fun formatTick(value: Double): String = when {
    value >= 100 -> "%.0f".format(value)
    value >= 10 -> "%.1f".format(value)
    value >= 1 -> "%.2f".format(value)
    else -> "%.3f".format(value)
}
