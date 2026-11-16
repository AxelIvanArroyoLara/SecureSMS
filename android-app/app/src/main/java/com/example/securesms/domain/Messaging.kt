/** Casos de uso para enviar, recibir y asociar claves desde cualquier interfaz. */
package com.example.securesms.domain

import com.example.securesms.crypto.CryptoContext
import com.example.securesms.crypto.CryptoRegistry
import com.example.securesms.crypto.CryptoResult
import com.example.securesms.crypto.HistoryVault
import com.example.securesms.crypto.KeyProfile
import com.example.securesms.crypto.Suite
import com.example.securesms.crypto.fingerprint
import com.example.securesms.crypto.fingerprintText
import com.example.securesms.protocol.Assembler
import com.example.securesms.protocol.Envelope
import com.example.securesms.protocol.SmsProtocol
import com.example.securesms.transport.SimulationTransport
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.util.Base64
import java.util.UUID

class Messaging(
    private val store: MessageStore,
    private val crypto: CryptoRegistry,
    private val history: HistoryVault,
    private val assembler: Assembler,
    private val sms: MessageTransport
) {
    private val keyLock = Mutex()
    private val encoder = Base64.getUrlEncoder().withoutPadding()

    fun profiles(mode: Mode): List<KeyProfile> =
        KeyProfile.entries.filter { crypto.find(mode.suite(), it) != null }

    fun demoConversation(owner: String): Conversation {
        require(owner == "Alice" || owner == "Bob")
        return conversation(Mode.DEMO, owner, if (owner == "Alice") "Bob" else "Alice")
    }

    suspend fun createSms(peer: String): Conversation? {
        val number = peer.trim()
        if (!e164.matches(number)) return null
        return conversation(Mode.SMS, "Device", number).also { store.save(it) }
    }

    suspend fun generate(profile: KeyProfile): String? = keyLock.withLock {
        val engine = crypto.find(Suite.HYBRID_V1, profile) ?: return "Crypto engine unavailable"
        if (store.identity(profile) != null) return null
        val alias = "securesms.identity.${profile.wire}.${UUID.randomUUID()}"
        when (val result = engine.generate(profile, alias)) {
            is CryptoResult.Failure -> result.error.description
            is CryptoResult.Ok -> {
                store.save(IdentityKey(profile, result.value.alias, result.value.publicKey))
                null
            }
        }
    }

    fun export(key: IdentityKey): String =
        "SSK1.${key.profile.wire}.${encoder.encodeToString(key.spki)}"

    suspend fun import(peer: String, share: String): String? = keyLock.withLock {
        if (!e164.matches(peer)) return "Enter an international phone number"
        if (share.length > 1030) return "Invalid public key format"
        val fields = share.trim().split('.', limit = 3)
        if (fields.size != 3 || fields[0] != "SSK1") return "Invalid public key format"
        val profile = KeyProfile.entries.firstOrNull { it.wire.toString() == fields[1] }
            ?: return "Unsupported key profile"
        val spki = try {
            Base64.getUrlDecoder().decode(fields[2])
        } catch (_: IllegalArgumentException) {
            return "Invalid public key encoding"
        }
        if (encoder.encodeToString(spki) != fields[2]) return "Invalid public key encoding"
        val engine = crypto.find(Suite.HYBRID_V1, profile) ?: return "Crypto engine unavailable"
        when (val result = engine.validatePublicKey(profile, spki)) {
            is CryptoResult.Failure -> result.error.description
            is CryptoResult.Ok -> {
                val previous = store.key(peer, profile)
                val verified = previous?.verified == true && previous.spki.contentEquals(spki)
                store.save(ContactKey(peer, profile, spki, verified))
                store.save(conversation(Mode.SMS, "Device", peer))
                null
            }
        }
    }

    suspend fun verify(key: ContactKey): String? = keyLock.withLock {
        val current = store.key(key.peer, key.profile)
        if (current == null || !current.spki.contentEquals(key.spki)) return "The contact key changed"
        store.save(current.copy(verified = true))
        null
    }

    suspend fun send(chat: Conversation, profile: KeyProfile, text: String, scenario: Scenario): String? {
        if (text.isBlank()) return "Enter a message"
        val body = text.encodeToByteArray()
        if (body.size > SmsProtocol.maxPlaintextBytes) return "Messages are limited to 1,024 UTF-8 bytes"
        val suite = chat.mode.suite()
        val engine = crypto.find(suite, profile) ?: return "Crypto engine unavailable"
        val spki = if (chat.mode == Mode.DEMO) {
            val identity = engine.generate(profile, chat.peer) as? CryptoResult.Ok
            identity?.value?.publicKey ?: return "Demo key unavailable"
        } else {
            val key = store.key(chat.peer, profile) ?: return "Import the recipient's ${profile.label} key"
            if (!key.verified) return "Verify the recipient's fingerprint before sending"
            key.spki
        }
        val id = UUID.randomUUID()
        val context = CryptoContext(id, suite, profile, fingerprint(spki))
        val result = when (val encrypted = engine.encrypt(context, spki, body)) {
            is CryptoResult.Failure -> return encrypted.error.description
            is CryptoResult.Ok -> encrypted
        }
        val envelope = Envelope(context, result.value)
        val frames = try {
            SmsProtocol.segment(envelope)
        } catch (_: IllegalArgumentException) {
            return "The encrypted payload exceeds the protocol limits"
        }
        val rowId = rowId(chat, id.toString(), true)
        val sealed = history.seal(rowId, body) ?: return "Could not protect local message history"
        store.save(chat)
        store.save(
            Message(
                rowId, chat.id, id.toString(), true, System.currentTimeMillis(),
                Status.QUEUED, suite.smsCapable, fingerprintText(context.recipientFingerprint),
                Diagnostics(profile, frames.size, SmsProtocol.encode(envelope).size, body.size, result.elapsedNanos),
                sealed
            )
        )
        val transport = if (chat.mode == Mode.SMS) sms else SimulationTransport(
            scenario, { from, to, frame -> receive(Mode.DEMO, from, to, frame) }, store::receipt
        )
        val error = transport.send(OutboundBatch(id, chat.owner, chat.peer, frames, suite.smsCapable))
        if (error != null) store.fail(id, error)
        return null
    }

    suspend fun receive(mode: Mode, from: String, to: String, text: String) {
        val chat = conversation(mode, to, from)
        assembler.accept(chat.id, text, { store.contains(rowId(chat, it, false)) }) { envelope, count ->
            val context = envelope.context
            val suite = mode.suite()
            if (context.suite != suite) return@accept
            val engine = crypto.find(suite, context.profile)
            val alias = if (mode == Mode.DEMO) to else store.identity(context.profile)
                ?.takeIf { fingerprint(it.spki).contentEquals(context.recipientFingerprint) }?.alias
            val result = if (engine != null && alias != null) engine.decrypt(context, alias, envelope.payload) else null
            val id = rowId(chat, context.id.toString(), false)
            val plaintext = (result as? CryptoResult.Ok)?.value
            val valid = plaintext?.takeIf {
                it.size in 1..SmsProtocol.maxPlaintextBytes &&
                    runCatching { it.decodeToString(throwOnInvalidSequence = true) }.isSuccess
            }
            val sealed = valid?.let { history.seal(id, it) }
            val error = when {
                engine == null -> "Crypto engine unavailable"
                alias == null -> "No matching private key on this device"
                result is CryptoResult.Failure -> result.error.description
                valid == null -> "Invalid decrypted message"
                sealed == null -> "Could not protect local message history"
                else -> null
            }
            store.save(chat)
            store.save(
                Message(
                    id, chat.id, context.id.toString(), false, System.currentTimeMillis(),
                    if (error == null) Status.RECEIVED else Status.DECRYPTION_FAILED,
                    suite.smsCapable, fingerprintText(context.recipientFingerprint),
                    Diagnostics(context.profile, count, SmsProtocol.encode(envelope).size,
                        valid?.size, decryptionNanos = (result as? CryptoResult.Ok)?.elapsedNanos),
                    sealed, error
                )
            )
        }
    }

    fun body(message: Message): String? = message.sealedBody?.let { history.open(message.rowId, it) }

    private fun Mode.suite() = if (this == Mode.DEMO) Suite.MOCK else Suite.HYBRID_V1
    private fun rowId(chat: Conversation, id: String, outgoing: Boolean) = "${chat.id}:$id:$outgoing"
    private fun conversation(mode: Mode, owner: String, peer: String) =
        Conversation("${mode.name}:$owner:$peer", mode, owner, peer)
}
