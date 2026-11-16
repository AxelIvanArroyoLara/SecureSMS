/** Canal local con dos participantes y fallos reproducibles de transporte. */
package com.example.securesms.transport

import com.example.securesms.domain.MessageTransport
import com.example.securesms.domain.OutboundBatch
import com.example.securesms.domain.Receipt
import com.example.securesms.domain.Scenario
import com.example.securesms.domain.Status
import kotlinx.coroutines.delay

/** Emite las mismas tramas y confirmaciones que consume el canal SMS. */
class SimulationTransport(
    private val scenario: Scenario,
    private val incoming: suspend (from: String, to: String, text: String) -> Unit,
    private val receipt: suspend (Receipt) -> Unit,
    private val latencyMillis: Long = 75
) : MessageTransport {
    override suspend fun send(batch: OutboundBatch): String? {
        delay(latencyMillis)
        if (scenario == Scenario.FAILURE) return "Simulated send failure"
        val indexed = batch.frames.withIndex().toList()
        indexed.forEach { receipt(Receipt(batch.id, it.index, Status.SENT)) }
        val sequence = when (scenario) {
            Scenario.NORMAL -> indexed
            Scenario.REORDER_DUPLICATE -> indexed.reversed().flatMap { listOf(it, it) }
            Scenario.MISSING -> indexed.dropLast(1)
            Scenario.FAILURE -> emptyList()
        }
        for ((index, frame) in sequence) {
            delay(latencyMillis)
            incoming(batch.from, batch.to, frame)
            receipt(Receipt(batch.id, index, Status.DELIVERED))
        }
        if (scenario == Scenario.MISSING) {
            receipt(Receipt(batch.id, indexed.last().index, Status.FAILED, "Simulated missing segment"))
        }
        return null
    }
}
