/** Canal Android SMS y receptores que sobreviven a la recreación del proceso. */
package com.example.securesms.transport

import android.Manifest
import android.annotation.SuppressLint
import android.app.Activity
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.Telephony
import android.telephony.PhoneNumberUtils
import android.telephony.SmsManager
import android.telephony.SmsMessage
import android.telephony.SubscriptionManager
import android.telephony.TelephonyManager
import com.example.securesms.SecureSmsApplication
import com.example.securesms.crypto.Suite
import com.example.securesms.domain.MessageTransport
import com.example.securesms.domain.Mode
import com.example.securesms.domain.OutboundBatch
import com.example.securesms.domain.Receipt
import com.example.securesms.domain.Status
import com.example.securesms.domain.e164
import com.example.securesms.protocol.SmsProtocol
import kotlinx.coroutines.launch
import java.util.Locale
import java.util.UUID

/** Usa un SMS físico por trama para tolerar pérdida y reordenación independientes. */
class SmsTransport(private val context: Context) : MessageTransport {
    fun availability(): String? = when {
        !context.packageManager.hasSystemFeature(
            if (Build.VERSION.SDK_INT >= 33) PackageManager.FEATURE_TELEPHONY_MESSAGING
            else PackageManager.FEATURE_TELEPHONY
        ) ->
            "This device does not support SMS"
        context.checkSelfPermission(Manifest.permission.SEND_SMS) != PackageManager.PERMISSION_GRANTED ->
            "Grant SMS permissions to send"
        !SubscriptionManager.isValidSubscriptionId(SubscriptionManager.getDefaultSmsSubscriptionId()) ->
            "Choose an active default SIM for SMS"
        else -> null
    }

    @SuppressLint("MissingPermission")
    @Suppress("DEPRECATION")
    override suspend fun send(batch: OutboundBatch): String? {
        if (!batch.smsCapable) return "Simulation data is blocked from carrier SMS"
        if (!e164.matches(batch.to)) return "Enter an international phone number"
        availability()?.let { return it }
        val subscription = SubscriptionManager.getDefaultSmsSubscriptionId()
        return try {
            val manager = if (Build.VERSION.SDK_INT >= 31) {
                context.getSystemService(SmsManager::class.java).createForSubscriptionId(subscription)
            } else {
                SmsManager.getSmsManagerForSubscriptionId(subscription)
            }
            // Prevalida el lote completo antes de enviar el primer segmento.
            val frames = batch.frames.mapNotNull(SmsProtocol::parse)
            val envelope = SmsProtocol.reassemble(frames)
            if (frames.size != batch.frames.size || envelope?.context?.suite != Suite.HYBRID_V1 ||
                envelope.context.id != batch.id || frames.withIndex().any { it.index != it.value.index }
            ) return "Invalid SecureSMS frame batch"
            if (batch.frames.any { manager.divideMessage(it).size != 1 }) {
                return "Carrier segmentation is incompatible with the frame size"
            }
            batch.frames.forEachIndexed { index, frame ->
                manager.sendTextMessage(
                    batch.to, null, frame,
                    callback(batch.id, index, false),
                    callback(batch.id, index, true)
                )
            }
            null
        } catch (_: SecurityException) {
            "SMS permission or installer policy denied access"
        } catch (_: IllegalArgumentException) {
            "The carrier rejected the SMS arguments"
        } catch (_: UnsupportedOperationException) {
            "SMS is unavailable on this device"
        } catch (_: IllegalStateException) {
            "The Android SMS service is unavailable"
        }
    }

    private fun callback(id: UUID, index: Int, delivery: Boolean): PendingIntent {
        val intent = Intent(context, SmsStatusReceiver::class.java)
            .setData(Uri.parse("securesms://receipt/$id/$index/${if (delivery) "delivery" else "sent"}"))
        val mutability = if (delivery && Build.VERSION.SDK_INT >= 31) {
            PendingIntent.FLAG_MUTABLE
        } else if (delivery) {
            0
        } else {
            PendingIntent.FLAG_IMMUTABLE
        }
        return PendingIntent.getBroadcast(context, 0, intent, PendingIntent.FLAG_ONE_SHOT or mutability)
    }
}

/** Consume únicamente el broadcast del sistema y descarta los SMS ajenos al protocolo. */
class SmsIncomingReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Telephony.Sms.Intents.SMS_RECEIVED_ACTION) return
        val parts = Telephony.Sms.Intents.getMessagesFromIntent(intent)
        val raw = parts.firstOrNull()?.originatingAddress ?: return
        if (parts.any { it.originatingAddress != raw }) return
        val text = parts.joinToString("") { it.messageBody.orEmpty() }
        if (SmsProtocol.parse(text) == null) return
        val country = context.getSystemService(TelephonyManager::class.java).networkCountryIso
            .uppercase(Locale.ROOT)
        val sender = raw.takeIf(e164::matches)
            ?: PhoneNumberUtils.formatNumberToE164(raw, country)?.takeIf(e164::matches) ?: return
        val app = context.applicationContext as SecureSmsApplication
        val pending = goAsync()
        app.scope.launch {
            try {
                app.messaging.receive(Mode.SMS, sender, "Device", text)
            } finally {
                pending.finish()
            }
        }
    }
}

/** Combina callbacks persistentes sin asumir que el operador informa la entrega. */
class SmsStatusReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val path = intent.data?.pathSegments ?: return
        if (path.size != 3) return
        val id = runCatching { UUID.fromString(path[0]) }.getOrNull() ?: return
        val index = path[1].toIntOrNull() ?: return
        val code = resultCode
        val receipt = when (path[2]) {
            "sent" -> if (code == Activity.RESULT_OK) Receipt(id, index, Status.SENT)
                else Receipt(id, index, Status.FAILED, "Android SMS send error ($code)")
            "delivery" -> {
                val pdu = intent.getByteArrayExtra("pdu") ?: return
                val format = intent.getStringExtra("format") ?: return
                val report = SmsMessage.createFromPdu(pdu, format) ?: return
                if (!report.isStatusReportMessage || code != Activity.RESULT_OK) return
                when (report.status) {
                    0 -> Receipt(id, index, Status.DELIVERED)
                    in 64..127 -> Receipt(id, index, Status.FAILED, "Carrier delivery error (${report.status})")
                    else -> return
                }
            }
            else -> return
        }
        val app = context.applicationContext as SecureSmsApplication
        val pending = goAsync()
        app.scope.launch {
            try {
                app.store.receipt(receipt)
            } finally {
                pending.finish()
            }
        }
    }
}
