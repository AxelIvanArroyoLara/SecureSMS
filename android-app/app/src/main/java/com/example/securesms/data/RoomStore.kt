/** Repositorio Room con transiciones de entrega atómicas e idempotentes. */
package com.example.securesms.data

import androidx.room.withTransaction
import com.example.securesms.crypto.KeyProfile
import com.example.securesms.domain.ContactKey
import com.example.securesms.domain.Conversation
import com.example.securesms.domain.Diagnostics
import com.example.securesms.domain.IdentityKey
import com.example.securesms.domain.Message
import com.example.securesms.domain.MessageStore
import com.example.securesms.domain.Receipt
import com.example.securesms.domain.Status
import com.example.securesms.protocol.Frame
import com.example.securesms.protocol.PendingFrame
import com.example.securesms.protocol.PendingStore
import kotlinx.coroutines.flow.map
import java.util.UUID

class RoomStore(private val db: SecureDatabase) : MessageStore, PendingStore {
    private val dao = db.messages()

    override fun conversations() = dao.conversations().map { rows ->
        rows.map { Conversation(it.id, it.mode, it.owner, it.peer) }
    }
    override fun keys() = dao.keys().map { rows -> rows.map { it.domain() } }
    override fun identities() = dao.identities().map { rows -> rows.map { it.domain() } }
    override fun messages() = dao.messages().map { rows ->
        rows.map {
            Message(
                it.rowId, it.conversationId, it.wireId, it.outgoing, it.createdAt, it.status,
                it.secure, it.fingerprint,
                Diagnostics(it.profile, it.segments, it.payloadBytes, it.plaintextBytes, it.encryptionNanos, it.decryptionNanos),
                it.sealedBody, it.error
            )
        }
    }

    override suspend fun save(conversation: Conversation) =
        dao.insert(ConversationRow(conversation.id, conversation.mode, conversation.owner, conversation.peer))

    override suspend fun save(message: Message) = with(message) {
        dao.insert(MessageRow(
            rowId, conversationId, wireId, outgoing, createdAt, status, secure, fingerprint, diagnostics.profile,
            diagnostics.segments, diagnostics.payloadBytes, diagnostics.plaintextBytes,
            diagnostics.encryptionNanos, diagnostics.decryptionNanos, sealedBody, error
        ))
    }

    override suspend fun save(key: ContactKey) = dao.put(ContactKeyRow(key.peer, key.profile, key.spki, key.verified))
    override suspend fun save(key: IdentityKey) = dao.put(IdentityKeyRow(key.profile, key.alias, key.spki))
    override suspend fun key(peer: String, profile: KeyProfile) = dao.contact(peer, profile)?.domain()
    override suspend fun identity(profile: KeyProfile) = dao.identity(profile)?.domain()
    override suspend fun contains(id: String) = dao.contains(id)

    override suspend fun receipt(receipt: Receipt) = db.withTransaction {
        val id = receipt.id.toString()
        val message = dao.outgoing(id) ?: return@withTransaction
        if (message.status in setOf(Status.FAILED, Status.DELIVERED) || receipt.index !in 0 until message.segments) {
            return@withTransaction
        }
        if (receipt.status == Status.FAILED) {
            dao.update(message.rowId, Status.FAILED, receipt.detail)
            return@withTransaction
        }
        if (receipt.status !in setOf(Status.SENT, Status.DELIVERED)) return@withTransaction
        val existing = dao.receipts(id).associateBy(ReceiptRow::part)
        if (existing[receipt.index]?.status != Status.DELIVERED) {
            dao.put(ReceiptRow(id, receipt.index, receipt.status))
        }
        val receipts = dao.receipts(id)
        if (receipts.size == message.segments) {
            val status = if (receipts.all { it.status == Status.DELIVERED }) Status.DELIVERED else Status.SENT
            dao.update(message.rowId, status, null)
        }
    }

    override suspend fun fail(id: UUID, detail: String) = db.withTransaction {
        val message = dao.outgoing(id.toString()) ?: return@withTransaction
        if (message.status != Status.DELIVERED) dao.update(message.rowId, Status.FAILED, detail)
    }

    suspend fun expireSends(before: Long) = dao.expireSends(before)
    override suspend fun expire(before: Long) = dao.expire(before)
    override suspend fun batches() = dao.batches()
    override suspend fun ready() = dao.ready().map { it.route to it.wireId }
    override suspend fun load(route: String, id: String) = dao.pending(route, id).map {
        PendingFrame(it.route, Frame(UUID.fromString(it.wireId), it.part, it.total, it.chunk), it.firstSeen)
    }
    override suspend fun add(frame: PendingFrame) = dao.insert(
        PendingRow(frame.route, frame.frame.id.toString(), frame.frame.index, frame.frame.total, frame.frame.chunk, frame.firstSeen)
    )
    override suspend fun remove(route: String, id: String) = dao.remove(route, id)

    private fun ContactKeyRow.domain() = ContactKey(peer, profile, spki, verified)
    private fun IdentityKeyRow.domain() = IdentityKey(profile, alias, spki)
}
