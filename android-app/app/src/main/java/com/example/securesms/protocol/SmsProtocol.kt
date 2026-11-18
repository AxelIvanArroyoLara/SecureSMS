/** Formato binario autenticable y tramas GSM-7 del protocolo SecureSMS v1. */
package com.example.securesms.protocol

import com.example.securesms.crypto.CipherPayload
import com.example.securesms.crypto.CryptoContext
import com.example.securesms.crypto.KeyProfile
import com.example.securesms.crypto.Suite
import java.nio.ByteBuffer
import java.util.Base64
import java.util.UUID

data class Envelope(val context: CryptoContext, val payload: CipherPayload)
data class Frame(val id: UUID, val index: Int, val total: Int, val chunk: String)

/** Valida tamaños y codificaciones antes de asignar memoria o invocar el motor. */
object SmsProtocol {
    const val maxEnvelopeBytes = 2048
    const val maxPlaintextBytes = 1024
    const val ttlMillis = 15 * 60 * 1000L
    const val maxPendingBatches = 64
    private const val headerSize = 51
    private const val chunkSize = 128
    private const val maxEncodedSize = (maxEnvelopeBytes * 4 + 2) / 3
    private const val maxFrames = (maxEncodedSize + chunkSize - 1) / chunkSize
    private val alphabet = Regex("[A-Za-z0-9_-]+")
    private val digits = Regex("[0-9a-z]{2}")
    private val encoder = Base64.getUrlEncoder().withoutPadding()
    private val decoder = Base64.getUrlDecoder()

    fun encode(envelope: Envelope): ByteArray {
        val (context, payload) = envelope
        val size = headerSize + 2 + payload.metadata.size + payload.ciphertext.size
        require(context.recipientFingerprint.size == 32)
        require(size <= maxEnvelopeBytes && payload.metadata.size in 1..768 && payload.ciphertext.isNotEmpty())
        return ByteBuffer.allocate(size)
            .put(context.authenticatedHeader())
            .putShort(payload.metadata.size.toShort())
            .put(payload.metadata)
            .put(payload.ciphertext)
            .array()
    }

    fun decode(bytes: ByteArray): Envelope? {
        if (bytes.size !in (headerSize + 4)..maxEnvelopeBytes) return null
        val buffer = ByteBuffer.wrap(bytes)
        if (buffer.get().toInt() != 1) return null
        val suiteId = buffer.get().toInt()
        val profileId = buffer.get().toInt()
        val suite = Suite.entries.firstOrNull { it.wire == suiteId } ?: return null
        val profile = KeyProfile.entries.firstOrNull { it.wire == profileId } ?: return null
        val id = UUID(buffer.long, buffer.long)
        val fingerprint = ByteArray(32).also { buffer.get(it) }
        val size = buffer.short.toInt()
        if (size !in 1..768 || size >= buffer.remaining()) return null
        val metadata = ByteArray(size).also { buffer.get(it) }
        val ciphertext = ByteArray(buffer.remaining()).also { buffer.get(it) }
        return Envelope(CryptoContext(id, suite, profile, fingerprint), CipherPayload(metadata, ciphertext))
    }

    fun segment(envelope: Envelope): List<String> {
        val id = envelope.context.id
        val wireId = encoder.encodeToString(
            ByteBuffer.allocate(16).putLong(id.mostSignificantBits).putLong(id.leastSignificantBits).array()
        )
        val chunks = encoder.encodeToString(encode(envelope)).chunked(chunkSize)
        return chunks.mapIndexed { index, chunk ->
            "S1.$wireId.${index.toString(36).padStart(2, '0')}.${chunks.size.toString(36).padStart(2, '0')}.$chunk"
        }
    }

    fun parse(text: String): Frame? {
        if (text.length !in 33..160) return null
        val fields = text.split('.', limit = 5)
        if (fields.size != 5 || fields[0] != "S1" || fields[1].length != 22) return null
        if (!digits.matches(fields[2]) || !digits.matches(fields[3])) return null
        val index = fields[2].toInt(36)
        val total = fields[3].toInt(36)
        val chunk = fields[4]
        if (total !in 1..maxFrames || index !in 0 until total) return null
        if (chunk.length !in 1..chunkSize || !alphabet.matches(chunk)) return null
        if (index != total - 1 && chunk.length != chunkSize) return null
        if (index == total - 1 && (total - 1) * chunkSize + chunk.length > maxEncodedSize) return null
        val key = ByteBuffer.wrap(decodeBase64(fields[1]) ?: return null)
        return Frame(UUID(key.long, key.long), index, total, chunk)
    }

    fun reassemble(frames: Collection<Frame>): Envelope? {
        val first = frames.firstOrNull() ?: return null
        if (first.total !in 1..maxFrames || frames.size != first.total) return null
        val sorted = frames.sortedBy(Frame::index)
        if (sorted.withIndex().any { (index, frame) ->
            frame.id != first.id || frame.total != first.total || index != frame.index ||
                frame.chunk.length !in 1..chunkSize || !alphabet.matches(frame.chunk) ||
                (index < first.total - 1 && frame.chunk.length != chunkSize)
        }) return null
        val encoded = sorted.joinToString("") { it.chunk }
        if (encoded.length > maxEncodedSize) return null
        return decode(decodeBase64(encoded) ?: return null)?.takeIf { it.context.id == first.id }
    }

    private fun decodeBase64(value: String): ByteArray? {
        if (!alphabet.matches(value)) return null
        return try {
            decoder.decode(value).takeIf { encoder.encodeToString(it) == value }
        } catch (_: IllegalArgumentException) {
            null
        }
    }
}
