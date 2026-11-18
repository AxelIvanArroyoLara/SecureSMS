/** Estado observable y acciones de usuario de las pantallas de mensajería. */
package com.example.securesms.presentation

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.securesms.SecureSmsApplication
import com.example.securesms.crypto.KeyProfile
import com.example.securesms.domain.ContactKey
import com.example.securesms.domain.Conversation
import com.example.securesms.domain.IdentityKey
import com.example.securesms.domain.Message
import com.example.securesms.domain.Mode
import com.example.securesms.domain.Scenario
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

data class DisplayMessage(val message: Message, val body: String?)
data class Inbox(
    val conversations: List<Conversation> = emptyList(),
    val messages: List<DisplayMessage> = emptyList(),
    val contacts: List<ContactKey> = emptyList(),
    val identities: List<IdentityKey> = emptyList()
)

class MessagingViewModel(application: Application) : AndroidViewModel(application) {
    private val app = application as SecureSmsApplication
    private val messaging = app.messaging
    val inbox = combine(app.store.conversations(), app.store.messages(), app.store.keys(), app.store.identities()) {
            conversations, messages, contacts, identities ->
        Inbox(conversations, messages.map { DisplayMessage(it, messaging.body(it)) }, contacts, identities)
    }.flowOn(Dispatchers.IO).stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), Inbox())

    private val _activeChat = MutableStateFlow<Conversation?>(null)
    val activeChat = _activeChat.asStateFlow()
    private val _busy = MutableStateFlow(false)
    val busy = _busy.asStateFlow()
    private val _notice = MutableStateFlow<String?>(null)
    val notice = _notice.asStateFlow()

    fun profiles(mode: Mode) = messaging.profiles(mode)
    fun select(chat: Conversation?) { _activeChat.value = chat }
    fun demo(owner: String) = select(messaging.demoConversation(owner))
    fun clearNotice() { _notice.value = null }
    fun share(key: IdentityKey) = messaging.export(key)
    fun smsAvailability() = app.sms.availability()

    fun newSms(peer: String, ready: () -> Unit) = action(ready) {
        val chat = messaging.createSms(peer) ?: return@action "Use international format, e.g. +525512345678"
        select(chat)
        null
    }

    fun generate(profile: KeyProfile) = action { messaging.generate(profile) }
    fun import(peer: String, text: String, done: () -> Unit) = action(done) {
        messaging.import(peer.trim(), text)
    }
    fun verify(key: ContactKey) = action { messaging.verify(key) }
    fun send(chat: Conversation, profile: KeyProfile, text: String, scenario: Scenario, done: () -> Unit) =
        action(done) { messaging.send(chat, profile, text, scenario) }

    private fun action(done: () -> Unit = {}, work: suspend () -> String?) {
        if (!_busy.compareAndSet(false, true)) return
        viewModelScope.launch {
            try {
                val error = app.scope.async { work() }.await()
                if (error == null) done() else _notice.value = error
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                _notice.value = "Unable to complete the operation"
            } finally {
                _busy.value = false
            }
        }
    }
}
