/** Verificación de serialización, límites y reconstrucción de tramas. */
package com.example.securesms

import com.example.securesms.crypto.CipherPayload
import com.example.securesms.crypto.CryptoContext
import com.example.securesms.crypto.KeyProfile
import com.example.securesms.crypto.Suite
import com.example.securesms.protocol.Assembler
import com.example.securesms.protocol.Envelope
import com.example.securesms.protocol.PendingFrame
import com.example.securesms.protocol.PendingStore
import com.example.securesms.protocol.SmsProtocol
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import java.util.UUID

class ProtocolTest {
    @Test
    fun roundTripAtMaximumEnvelopeSize() {
        val envelope = envelope(2048 - 53 - 32)
        val encoded = SmsProtocol.encode(envelope)
        assertEquals(2048, encoded.size)
        val frames = SmsProtocol.segment(envelope)
        assertEquals(22, frames.size)
        assertTrue(frames.all { it.length <= 160 })
        val decoded = SmsProtocol.reassemble(frames.reversed().map { SmsProtocol.parse(it)!! })!!
        assertArrayEquals(encoded, SmsProtocol.encode(decoded))
    }

    @Test
    fun rejectsMalformedUnsupportedOversizedAndInconsistentInput() {
        val envelope = envelope(500)
        val wire = SmsProtocol.segment(envelope)
        assertNull(SmsProtocol.parse(wire.first().replaceFirst("S1", "S2")))
        assertNull(SmsProtocol.parse(wire.first() + "A"))
        assertNull(SmsProtocol.parse(wire.first().dropLast(1)))
        assertNull(SmsProtocol.parse(wire.last() + "!"))
        assertNull(SmsProtocol.parse(wire.first().replace(".00.", ".zz.")))
        val frames = wire.map { SmsProtocol.parse(it)!! }
        assertNull(SmsProtocol.reassemble(frames.dropLast(1)))
        assertNull(SmsProtocol.reassemble(frames.dropLast(1) + frames.first()))
        assertNull(SmsProtocol.reassemble(frames.dropLast(1) + frames.last().copy(id = UUID.randomUUID())))
        val encoded = SmsProtocol.encode(envelope)
        assertNull(SmsProtocol.decode(encoded.copyOf().apply { this[0] = 2 }))
        assertNull(SmsProtocol.decode(encoded.copyOf().apply { this[1] = 9 }))
        assertNull(SmsProtocol.decode(encoded.copyOf().apply { this[51] = 127 }))
        assertNull(SmsProtocol.decode(ByteArray(2049)))
        assertThrows(IllegalArgumentException::class.java) { SmsProtocol.segment(envelope(2048)) }
    }

    @Test
    fun duplicateFramesAndMessagesAreIdempotent() = runBlocking {
        val store = MemoryPending()
        val assembler = Assembler(store)
        val seen = mutableSetOf<String>()
        val frames = SmsProtocol.segment(envelope(500))
        suspend fun accept(text: String) = assembler.accept("Alice:Bob", text, seen::contains) { message, size ->
            assertEquals(frames.size, size)
            assertTrue(seen.add(message.context.id.toString()))
        }
        accept(frames.last())
        accept(frames.last())
        accept(frames.last().dropLast(1) + (if (frames.last().endsWith("A")) "B" else "A"))
        assertEquals(1, store.rows.size)
        assertTrue(seen.isEmpty())
        frames.reversed().forEach { accept(it) }
        frames.forEach { accept(it) }
        assertEquals(1, seen.size)
        assertTrue(store.rows.isEmpty())
    }

    @Test
    fun scopesByRouteAndExpiresMissingFrames() = runBlocking {
        var time = SmsProtocol.ttlMillis
        val store = MemoryPending()
        val assembler = Assembler(store) { time }
        val frames = SmsProtocol.segment(envelope(500))
        assembler.accept("first", frames.first(), { false }) { _, _ -> error("Incomplete") }
        frames.drop(1).forEach { assembler.accept("other", it, { false }) { _, _ -> error("Wrong sender") } }
        time += SmsProtocol.ttlMillis
        frames.drop(1).forEach { assembler.accept("first", it, { false }) { _, _ -> error("Expired") } }
        assertEquals(frames.size - 1, store.rows.size)
    }

    @Test
    fun recoversCompleteBatchAfterInterruptedProcessing() = runBlocking {
        val store = MemoryPending()
        val message = envelope(220)
        val frames = SmsProtocol.segment(message).map { SmsProtocol.parse(it)!! }
        frames.forEach { store.add(PendingFrame("SMS:Device:+525512345678", it, 42L)) }
        var recovered = 0
        Assembler(store) { 43L }.recover { route, envelope, size ->
            assertEquals("SMS:Device:+525512345678", route)
            assertEquals(message.context.id, envelope.context.id)
            assertEquals(frames.size, size)
            recovered++
        }
        assertEquals(1, recovered)
        assertTrue(store.rows.isEmpty())
    }

    private fun envelope(bytes: Int) = Envelope(
        CryptoContext(UUID.randomUUID(), Suite.MOCK, KeyProfile.P256, ByteArray(32)),
        CipherPayload(ByteArray(32), ByteArray(bytes) { it.toByte() })
    )
}

private class MemoryPending : PendingStore {
    val rows = mutableListOf<PendingFrame>()
    override suspend fun expire(before: Long) { rows.removeAll { it.firstSeen <= before } }
    override suspend fun batches() = groups().size
    override suspend fun ready() = groups().filterValues { it.size == it.first().frame.total }.keys.toList()
    private fun groups() = rows.groupBy { it.route to it.frame.id.toString() }
    override suspend fun load(route: String, id: String) = rows.filter { it.route == route && it.frame.id.toString() == id }
    override suspend fun add(frame: PendingFrame) { rows.add(frame) }
    override suspend fun remove(route: String, id: String) {
        rows.removeAll { it.route == route && it.frame.id.toString() == id }
    }
}
