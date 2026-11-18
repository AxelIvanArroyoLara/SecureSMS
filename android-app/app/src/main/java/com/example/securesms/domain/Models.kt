/** Estados de mensajería y puertos de persistencia y transporte. */
package com.example.securesms.domain

import com.example.securesms.crypto.KeyProfile
import kotlinx.coroutines.flow.Flow
import java.util.UUID

enum class Mode { DEMO, SMS }
enum class Status(val label: String) {
    QUEUED("Sending"), SENT("Sent"), DELIVERED("Delivered"), FAILED("Failed"),
    RECEIVED("Received"), DECRYPTION_FAILED("Decryption failed")
}
enum class Scenario(val label: String) {
    NORMAL("Normal"), REORDER_DUPLICATE("Reorder + duplicate"),
    MISSING("Missing segment"), FAILURE("Send failure")
}

/** Cada segmento tiene confirmaciones independientes y puede llegar fuera de orden. */
data class Receipt(
    val id: UUID,
    val index: Int,
    val status: Status,
    val detail: String? = null
)

/** Lote con procedencia criptográfica exigida por el transporte real. */
class OutboundBatch internal constructor(
    val id: UUID,
    val from: String,
    val to: String,
    val frames: List<String>,
    val smsCapable: Boolean
)

fun interface MessageTransport {
    /** Devuelve un error para un lote rechazado antes de completar el envío. */
    suspend fun send(batch: OutboundBatch): String?
}

data class Conversation(val id: String, val mode: Mode, val owner: String, val peer: String)
data class Diagnostics(
    val profile: KeyProfile,
    val segments: Int,
    val payloadBytes: Int,
    val plaintextBytes: Int? = null,
    val encryptionNanos: Long? = null,
    val decryptionNanos: Long? = null
)
data class Message(
    val rowId: String,
    val conversationId: String,
    val wireId: String,
    val outgoing: Boolean,
    val createdAt: Long,
    val status: Status,
    val secure: Boolean,
    val fingerprint: String,
    val diagnostics: Diagnostics,
    val sealedBody: ByteArray? = null,
    val error: String? = null
)
data class ContactKey(val peer: String, val profile: KeyProfile, val spki: ByteArray, val verified: Boolean)
data class IdentityKey(val profile: KeyProfile, val alias: String, val spki: ByteArray)

/** Puerto que mantiene el historial y aplica transiciones de entrega atómicas. */
interface MessageStore {
    fun conversations(): Flow<List<Conversation>>
    fun messages(): Flow<List<Message>>
    fun keys(): Flow<List<ContactKey>>
    fun identities(): Flow<List<IdentityKey>>
    suspend fun save(conversation: Conversation)
    suspend fun save(message: Message)
    suspend fun save(key: ContactKey)
    suspend fun save(key: IdentityKey)
    suspend fun key(peer: String, profile: KeyProfile): ContactKey?
    suspend fun identity(profile: KeyProfile): IdentityKey?
    suspend fun contains(id: String): Boolean
    suspend fun receipt(receipt: Receipt)
    suspend fun fail(id: UUID, detail: String)
}

/** Forma canónica para crear conversaciones y asociar claves de contactos SMS. */
val e164 = Regex("\\+[1-9][0-9]{1,14}")
