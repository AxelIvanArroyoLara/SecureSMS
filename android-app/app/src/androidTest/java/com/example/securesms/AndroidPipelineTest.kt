/** Pruebas instrumentadas de Room, reensamblaje y proveedores Android Keystore. */
package com.example.securesms

import android.os.Build
import androidx.room.Room
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.example.securesms.crypto.*
import com.example.securesms.data.RoomStore
import com.example.securesms.data.SecureDatabase
import com.example.securesms.domain.*
import com.example.securesms.protocol.Assembler
import com.example.securesms.protocol.Envelope
import com.example.securesms.protocol.SmsProtocol
import com.example.securesms.transport.SmsTransport
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class AndroidPipelineTest {
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    @Test
    fun storePersistsHistoryKeysAndMonotonicDelivery() = runBlocking {
        val name = "test-${UUID.randomUUID()}.db"
        val conversation = Conversation("SMS:Device:+525512345678", Mode.SMS, "Device", "+525512345678")
        val id = UUID.randomUUID()
        val key = ContactKey(conversation.peer, KeyProfile.P256, byteArrayOf(1, 2, 3), true)
        val diagnostics = Diagnostics(KeyProfile.P256, 2, 480, 204, encryptionNanos = 1_000)
        try {
            Room.databaseBuilder(context, SecureDatabase::class.java, name).build().withDatabase { database ->
                val store = RoomStore(database)
                store.save(conversation)
                store.save(Message("row", conversation.id, id.toString(), true, 5L, Status.QUEUED, true, "fp", diagnostics))
                store.save(key)
                store.receipt(Receipt(id, 0, Status.DELIVERED))
                store.receipt(Receipt(id, 0, Status.SENT))
                assertEquals(Status.QUEUED, store.messages().first().single().status)
                store.receipt(Receipt(id, 1, Status.SENT))
                assertEquals(Status.SENT, store.messages().first().single().status)
            }
            Room.databaseBuilder(context, SecureDatabase::class.java, name).build().withDatabase { database ->
                val store = RoomStore(database)
                assertEquals(conversation, store.conversations().first().single())
                assertArrayEquals(key.spki, store.key(key.peer, key.profile)?.spki)
                assertTrue(store.key(key.peer, key.profile)?.verified == true)
                store.receipt(Receipt(id, 1, Status.DELIVERED))
                val message = store.messages().first().single()
                assertEquals(Status.DELIVERED, message.status)
                assertEquals(diagnostics, message.diagnostics)
            }
        } finally {
            context.deleteDatabase(name)
        }
        Unit
    }

    @Test
    fun demoReassemblesDuplicatesPersistsStatusesAndSealsHistory() = runBlocking {
        Room.inMemoryDatabaseBuilder(context, SecureDatabase::class.java).build().withDatabase { database ->
            val store = RoomStore(database)
            val service = Messaging(store, CryptoRegistry(DemoCrypto(Algorithm.ECC)), HistoryVault(), Assembler(store)) {
                error("Demo reached the carrier transport")
            }
            val text = "Universidad ".repeat(30)
            val chat = service.demoConversation("Alice")
            assertNull(service.send(chat, KeyProfile.P256, text, Scenario.REORDER_DUPLICATE))
            val delivered = store.messages().first()
            assertEquals(2, delivered.size)
            val incoming = delivered.single { !it.outgoing }
            val outgoing = delivered.single { it.outgoing }
            assertEquals(2, store.conversations().first().size)
            assertEquals(Status.DELIVERED, outgoing.status)
            assertEquals(Status.RECEIVED, incoming.status)
            assertEquals(text, service.body(incoming))
            assertFalse(text.encodeToByteArray().contentEquals(incoming.sealedBody))
            assertTrue(incoming.diagnostics.segments > 1)
            assertTrue(incoming.diagnostics.decryptionNanos!! > 0)
            assertEquals(0, store.batches())
            service.send(chat, KeyProfile.P256, text, Scenario.MISSING)
            service.send(chat, KeyProfile.P256, text, Scenario.FAILURE)
            assertEquals(2, store.messages().first().count { it.status == Status.FAILED })
            assertEquals(1, store.messages().first().count { !it.outgoing })
            assertEquals(1, store.batches())
        }
    }

    @Test
    fun carrierPipelineRequiresVerifiedKeyAndRejectsModifiedCiphertext() = runBlocking {
        Room.inMemoryDatabaseBuilder(context, SecureDatabase::class.java).build().withDatabase { database ->
            val store = RoomStore(database)
            val profile = KeyProfile.P256
            org.junit.Assume.assumeTrue(Build.VERSION.SDK_INT >= 31)
            val engine = HybridCrypto(Algorithm.ECC, AndroidIdentityVault(), setOf(profile))
            val batches = mutableListOf<OutboundBatch>()
            val service = Messaging(store, CryptoRegistry(engine), HistoryVault(), Assembler(store)) {
                batches.add(it)
                null
            }
            val peer = "+525512345678"
            val chat = service.createSms(peer)!!
            assertTrue(service.send(chat, profile, "sample", Scenario.NORMAL)!!.contains("Import"))
            assertNotNull(service.import(peer, "SSK1.3.Zg"))
            assertNull(service.generate(profile))
            val key = store.identity(profile)!!
            try {
                assertNull(service.import(peer, service.export(key)))
                assertTrue(service.send(chat, profile, "sample", Scenario.NORMAL)!!.contains("Verify"))
                assertTrue(batches.isEmpty())
                assertNull(service.verify(store.key(peer, profile)!!))
                assertNull(service.send(chat, profile, "sample", Scenario.NORMAL))
                val batch = batches.single()
                assertTrue(batch.smsCapable)
                assertEquals(chat.peer, batch.to)
                batch.frames.reversed().forEach { service.receive(Mode.SMS, peer, "Device", it) }
                assertEquals("sample", service.body(store.messages().first().single { !it.outgoing }))
                val original = SmsProtocol.reassemble(batch.frames.map { SmsProtocol.parse(it)!! })!!
                val modified = original.copy(context = original.context.copy(id = UUID.randomUUID()))
                SmsProtocol.segment(modified).forEach { service.receive(Mode.SMS, peer, "Device", it) }
                val failure = store.messages().first().single { it.status == Status.DECRYPTION_FAILED }
                assertNull(service.body(failure))
            } finally {
                KeyStore.getInstance("AndroidKeyStore").apply { load(null); deleteEntry(key.alias) }
            }
        }
    }

    @Test
    fun realTransportRejectsDemoBeforePlatformAccess() = runBlocking {
        val id = UUID.randomUUID()
        val batch = OutboundBatch(id, "Alice", "+525512345678", emptyList(), false)
        assertEquals("Simulation data is blocked from carrier SMS", SmsTransport(context).send(batch))
    }

    @Test
    fun keystoreHybridRoundTripWithAllSupportedProfiles() = runBlocking {
        val privateStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        for (profile in KeyProfile.entries) {
            if (Build.VERSION.SDK_INT < 31 && profile.algorithm == Algorithm.ECC) continue
            val engine = HybridCrypto(profile.algorithm, AndroidIdentityVault(), setOf(profile))
            val alias = "securesms.test.${UUID.randomUUID()}"
            try {
                val generated = engine.generate(profile, alias)
                assertTrue("$profile generate: $generated", generated is CryptoResult.Ok)
                val identity = (generated as CryptoResult.Ok).value
                assertNull(privateStore.getKey(alias, null).encoded)
                val cryptoContext = CryptoContext(UUID.randomUUID(), Suite.HYBRID_V1, profile, fingerprint(identity.publicKey))
                val plaintext = "Keystore round trip".encodeToByteArray()
                val encrypted = engine.encrypt(cryptoContext, identity.publicKey, plaintext)
                assertTrue("$profile encrypt: $encrypted", encrypted is CryptoResult.Ok)
                val envelope = Envelope(cryptoContext, (encrypted as CryptoResult.Ok).value)
                val frames = SmsProtocol.segment(envelope)
                val received = SmsProtocol.reassemble(frames.map { SmsProtocol.parse(it)!! })!!
                val decrypted = engine.decrypt(received.context, alias, received.payload)
                assertTrue("$profile decrypt: $decrypted", decrypted is CryptoResult.Ok)
                assertArrayEquals(plaintext, (decrypted as CryptoResult.Ok).value)
            } finally {
                privateStore.deleteEntry(alias)
            }
        }
    }
}

private inline fun SecureDatabase.withDatabase(block: (SecureDatabase) -> Unit) {
    try {
        block(this)
    } finally {
        close()
    }
}
