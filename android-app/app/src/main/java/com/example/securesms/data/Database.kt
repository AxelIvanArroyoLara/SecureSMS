/** Esquema Room y consultas para historial, claves, tramas y confirmaciones. */
package com.example.securesms.data

import androidx.room.Dao
import androidx.room.Database
import androidx.room.Entity
import androidx.room.Index
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query
import androidx.room.RoomDatabase
import androidx.room.Upsert
import com.example.securesms.crypto.KeyProfile
import com.example.securesms.domain.Mode
import com.example.securesms.domain.Status
import kotlinx.coroutines.flow.Flow

@Entity(tableName = "conversations")
data class ConversationRow(@PrimaryKey val id: String, val mode: Mode, val owner: String, val peer: String)

@Entity(tableName = "messages", indices = [Index("conversationId"), Index("wireId", "outgoing")])
data class MessageRow(
    @PrimaryKey val rowId: String,
    val conversationId: String,
    val wireId: String,
    val outgoing: Boolean,
    val createdAt: Long,
    val status: Status,
    val secure: Boolean,
    val fingerprint: String,
    val profile: KeyProfile,
    val segments: Int,
    val payloadBytes: Int,
    val plaintextBytes: Int?,
    val encryptionNanos: Long?,
    val decryptionNanos: Long?,
    val sealedBody: ByteArray?,
    val error: String?
)

@Entity(tableName = "contact_keys", primaryKeys = ["peer", "profile"])
data class ContactKeyRow(val peer: String, val profile: KeyProfile, val spki: ByteArray, val verified: Boolean)

@Entity(tableName = "identity_keys")
data class IdentityKeyRow(@PrimaryKey val profile: KeyProfile, val alias: String, val spki: ByteArray)

@Entity(tableName = "pending", primaryKeys = ["route", "wireId", "part"], indices = [Index("firstSeen")])
data class PendingRow(
    val route: String, val wireId: String, val part: Int, val total: Int, val chunk: String, val firstSeen: Long
)

data class PendingBatch(val route: String, val wireId: String)

@Entity(tableName = "receipts", primaryKeys = ["wireId", "part"])
data class ReceiptRow(val wireId: String, val part: Int, val status: Status)

@Dao
interface MessageDao {
    @Query("SELECT * FROM conversations ORDER BY peer") fun conversations(): Flow<List<ConversationRow>>
    @Query("SELECT * FROM messages ORDER BY createdAt, rowId") fun messages(): Flow<List<MessageRow>>
    @Query("SELECT * FROM contact_keys ORDER BY peer, profile") fun keys(): Flow<List<ContactKeyRow>>
    @Query("SELECT * FROM identity_keys ORDER BY profile") fun identities(): Flow<List<IdentityKeyRow>>

    @Insert(onConflict = OnConflictStrategy.IGNORE) suspend fun insert(row: ConversationRow)
    @Insert(onConflict = OnConflictStrategy.IGNORE) suspend fun insert(row: MessageRow)
    @Upsert suspend fun put(row: ContactKeyRow)
    @Upsert suspend fun put(row: IdentityKeyRow)
    @Upsert suspend fun put(row: ReceiptRow)

    @Query("SELECT * FROM contact_keys WHERE peer = :peer AND profile = :profile")
    suspend fun contact(peer: String, profile: KeyProfile): ContactKeyRow?

    @Query("SELECT * FROM identity_keys WHERE profile = :profile") suspend fun identity(profile: KeyProfile): IdentityKeyRow?
    @Query("SELECT EXISTS(SELECT 1 FROM messages WHERE rowId = :id)") suspend fun contains(id: String): Boolean
    @Query("SELECT * FROM messages WHERE wireId = :id AND outgoing = 1 LIMIT 1") suspend fun outgoing(id: String): MessageRow?
    @Query("SELECT * FROM receipts WHERE wireId = :id") suspend fun receipts(id: String): List<ReceiptRow>

    @Query("UPDATE messages SET status = :status, error = :detail WHERE rowId = :id")
    suspend fun update(id: String, status: Status, detail: String?)

    @Query("UPDATE messages SET status = 'FAILED', error = 'Send confirmation timed out' WHERE status = 'QUEUED' AND createdAt <= :before")
    suspend fun expireSends(before: Long)

    @Insert(onConflict = OnConflictStrategy.IGNORE) suspend fun insert(row: PendingRow)
    @Query("SELECT * FROM pending WHERE route = :route AND wireId = :id ORDER BY part")
    suspend fun pending(route: String, id: String): List<PendingRow>

    @Query("SELECT COUNT(*) FROM (SELECT route, wireId FROM pending GROUP BY route, wireId)") suspend fun batches(): Int
    @Query("SELECT route, wireId FROM pending GROUP BY route, wireId HAVING COUNT(*) = MAX(total)")
    suspend fun ready(): List<PendingBatch>

    @Query("DELETE FROM pending WHERE firstSeen <= :before") suspend fun expire(before: Long)
    @Query("DELETE FROM pending WHERE route = :route AND wireId = :id") suspend fun remove(route: String, id: String)
}

@Database(
    entities = [ConversationRow::class, MessageRow::class, ContactKeyRow::class, IdentityKeyRow::class,
        PendingRow::class, ReceiptRow::class],
    version = 1
)
abstract class SecureDatabase : RoomDatabase() {
    abstract fun messages(): MessageDao
}
