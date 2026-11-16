/** Pruebas del canal local y de las confirmaciones de cada trama. */
package com.example.securesms

import com.example.securesms.domain.OutboundBatch
import com.example.securesms.domain.Receipt
import com.example.securesms.domain.Scenario
import com.example.securesms.domain.Status
import com.example.securesms.transport.SimulationTransport
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import java.util.UUID

class SimulationTest {
    private val frames = listOf("first", "second")
    private val batch = OutboundBatch(UUID.randomUUID(), "Alice", "Bob", frames, false)

    @Test
    fun successAndDuplicateCallbacks() = runBlocking {
        val arrived = mutableListOf<String>()
        val receipts = mutableListOf<Receipt>()
        val transport = SimulationTransport(Scenario.REORDER_DUPLICATE, { from, to, text ->
            assertEquals("Alice", from)
            assertEquals("Bob", to)
            arrived.add(text)
        }, { receipts.add(it) }, 0)
        assertNull(transport.send(batch))
        assertEquals(listOf("second", "second", "first", "first"), arrived)
        assertEquals(listOf(Status.SENT, Status.SENT) + List(4) { Status.DELIVERED }, receipts.map { it.status })
    }

    @Test
    fun dropsFinalSegmentOrRejectsEntireSend() = runBlocking {
        val arrived = mutableListOf<String>()
        val receipts = mutableListOf<Receipt>()
        val missing = SimulationTransport(Scenario.MISSING, { _, _, text -> arrived.add(text) }, { receipts.add(it) }, 0)
        assertNull(missing.send(batch))
        assertEquals(listOf("first"), arrived)
        assertEquals(Status.FAILED, receipts.last().status)
        val rejected = SimulationTransport(Scenario.FAILURE, { _, _, _ -> error("Unexpected delivery") },
            { error("Unexpected callback") }, 0)
        assertEquals("Simulated send failure", rejected.send(batch))
    }
}
