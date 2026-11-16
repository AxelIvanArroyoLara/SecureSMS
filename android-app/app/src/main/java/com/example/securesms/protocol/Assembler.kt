/** Política de reensamblaje acotado, independiente del medio de transporte. */
package com.example.securesms.protocol

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

data class PendingFrame(val route: String, val frame: Frame, val firstSeen: Long)

interface PendingStore {
    suspend fun expire(before: Long)
    suspend fun batches(): Int
    suspend fun load(route: String, id: String): List<PendingFrame>
    suspend fun add(frame: PendingFrame)
    suspend fun remove(route: String, id: String)
}

/** La ruta incluye modo, remitente y destinatario lógico local. */
class Assembler(private val store: PendingStore, private val now: () -> Long = System::currentTimeMillis) {
    private val lock = Mutex()

    suspend fun accept(
        route: String,
        text: String,
        alreadyReceived: suspend (String) -> Boolean,
        onComplete: suspend (Envelope, Int) -> Unit
    ) {
        val frame = SmsProtocol.parse(text) ?: return
        lock.withLock {
            val time = now()
            store.expire(time - SmsProtocol.ttlMillis)
            val id = frame.id.toString()
            if (alreadyReceived(id)) {
                store.remove(route, id)
                return
            }
            val pending = store.load(route, id)
            if (pending.any { it.frame.total != frame.total }) return
            val existing = pending.firstOrNull { it.frame.index == frame.index }
            if (existing != null && existing.frame.chunk != frame.chunk) return
            if (pending.isEmpty() && store.batches() >= SmsProtocol.maxPendingBatches) return
            val frames = pending.map(PendingFrame::frame).toMutableList()
            if (existing == null) {
                store.add(PendingFrame(route, frame, pending.firstOrNull()?.firstSeen ?: time))
                frames.add(frame)
            }
            if (frames.size == frame.total) {
                SmsProtocol.reassemble(frames)?.let { onComplete(it, frames.size) }
                store.remove(route, id)
            }
        }
    }
}
