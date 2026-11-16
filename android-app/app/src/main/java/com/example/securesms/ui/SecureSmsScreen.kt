/** Navegación y pantallas Compose para conversaciones, claves y diagnóstico. */
package com.example.securesms.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.example.securesms.crypto.KeyProfile
import com.example.securesms.crypto.fingerprint
import com.example.securesms.crypto.fingerprintText
import com.example.securesms.domain.ContactKey
import com.example.securesms.domain.Conversation
import com.example.securesms.domain.Mode
import com.example.securesms.domain.Scenario
import com.example.securesms.domain.Status
import com.example.securesms.presentation.DisplayMessage
import com.example.securesms.presentation.Inbox
import com.example.securesms.presentation.MessagingViewModel
import com.example.securesms.protocol.SmsProtocol
import com.example.securesms.ui.theme.DeepTeal
import com.example.securesms.ui.theme.Mint
import java.text.DateFormat
import java.util.Date
import java.util.Locale

private enum class Section(val label: String, val marker: String) {
    INBOX("Inbox", "◫"), SETTINGS("Encryption", "◇"), KEYS("Keys", "⊞"), DIAGNOSTICS("Diagnostics", "≋")
}

@Composable
fun SecureSmsScreen(
    model: MessagingViewModel,
    permissionRevision: Int,
    requestSms: () -> Unit,
    share: (String) -> Unit
) {
    val inbox by model.inbox.collectAsState()
    val chat by model.activeChat.collectAsState()
    val busy by model.busy.collectAsState()
    val notice by model.notice.collectAsState()
    var section by rememberSaveable { mutableStateOf(Section.INBOX) }
    var mode by rememberSaveable { mutableStateOf(Mode.DEMO) }
    var profile by rememberSaveable { mutableStateOf(KeyProfile.RSA_2048) }
    var scenario by rememberSaveable { mutableStateOf(Scenario.NORMAL) }
    var diagnosticsId by rememberSaveable { mutableStateOf<String?>(null) }
    var newSms by rememberSaveable { mutableStateOf(false) }
    val snackbar = remember { SnackbarHostState() }
    val availability = remember(permissionRevision) { model.smsAvailability() }
    val profiles = model.profiles(mode)
    val selectedProfile = profile.takeIf { it in profiles } ?: profiles.firstOrNull()
    val showingChat = section == Section.INBOX && chat != null
    val exitChat = { model.select(null) }
    BackHandler(showingChat || section != Section.INBOX) {
        if (showingChat) exitChat() else section = Section.INBOX
    }
    LaunchedEffect(notice) {
        notice?.let { snackbar.showSnackbar(it); model.clearNotice() }
    }
    Scaffold(
        modifier = Modifier.imePadding(),
        snackbarHost = { SnackbarHost(snackbar) },
        bottomBar = {
            if (!showingChat) NavigationBar {
                Section.entries.forEach { item ->
                    NavigationBarItem(
                        selected = section == item,
                        onClick = { section = item },
                        icon = { Text(item.marker, style = MaterialTheme.typography.titleLarge) },
                        label = { Text(item.label, maxLines = 1) }
                    )
                }
            }
        }
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            Masthead(if (showingChat) chat?.peer.orEmpty() else "SecureSMS", mode, if (showingChat) exitChat else null)
            if (busy) LinearProgressIndicator(Modifier.fillMaxWidth())
            val active = chat
            when {
                showingChat && active != null -> Chat(
                    active, inbox.messages.filter { it.message.conversationId == active.id },
                    selectedProfile, busy, availability, scenario,
                    inbox.contacts.firstOrNull { it.peer == active.peer && it.profile == selectedProfile },
                    switchUser = { model.demo(active.peer) },
                    configure = { section = Section.SETTINGS },
                    manageKeys = { section = Section.KEYS },
                    inspect = {
                        diagnosticsId = it
                        section = Section.DIAGNOSTICS
                    },
                    send = { text, done -> selectedProfile?.let { model.send(active, it, text, scenario, done) } }
                )
                section == Section.INBOX -> Conversations(
                    mode, inbox, onMode = { mode = it; model.select(null) },
                    demo = model::demo, newSms = { newSms = true }, open = model::select
                )
                section == Section.SETTINGS -> Settings(
                    mode, profiles, selectedProfile, { profile = it }, scenario, { scenario = it },
                    availability, requestSms
                )
                section == Section.KEYS -> Keys(inbox, model, busy, share)
                section == Section.DIAGNOSTICS -> Diagnostics(
                    inbox.messages.filter { message ->
                        inbox.conversations.any { it.id == message.message.conversationId && it.mode == mode }
                    }, diagnosticsId
                )
            }
        }
    }
    if (newSms) {
        var number by rememberSaveable { mutableStateOf("") }
        AlertDialog(
            onDismissRequest = { newSms = false },
            title = { Text("New SMS conversation") },
            text = {
                OutlinedTextField(number, { number = it.take(32) }, label = { Text("International number") },
                    placeholder = { Text("+525512345678") }, singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Phone))
            },
            confirmButton = { Button(enabled = !busy, onClick = { model.newSms(number) { newSms = false } }) { Text("Open chat") } },
            dismissButton = { TextButton(onClick = { newSms = false }) { Text("Cancel") } }
        )
    }
}

@Composable
private fun Masthead(title: String, mode: Mode, back: (() -> Unit)?) {
    Surface(color = DeepTeal, contentColor = androidx.compose.ui.graphics.Color.White) {
        Column(Modifier.fillMaxWidth().padding(horizontal = 18.dp, vertical = 14.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                back?.let { TextButton(onClick = it) { Text("Back", color = Mint) } }
                Text(title, style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.SemiBold)
            }
            Text(
                if (mode == Mode.DEMO) "Offline demo  ·  Test transform, no encryption" else "Carrier SMS  ·  Hybrid encryption",
                color = Mint, style = MaterialTheme.typography.bodyMedium
            )
        }
    }
}

@Composable
private fun Conversations(
    mode: Mode,
    inbox: Inbox,
    onMode: (Mode) -> Unit,
    demo: (String) -> Unit,
    newSms: () -> Unit,
    open: (Conversation) -> Unit
) {
    val conversations = inbox.conversations.filter { it.mode == mode }
    val latest = inbox.messages.associateBy { it.message.conversationId }
    LazyColumn(
        modifier = Modifier.fillMaxSize().padding(horizontal = 18.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(vertical = 16.dp)
    ) {
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Mode.entries.forEach { option ->
                    if (mode == option) FilledTonalButton(onClick = { onMode(option) }) { Text(modeLabel(option)) }
                    else OutlinedButton(onClick = { onMode(option) }) { Text(modeLabel(option)) }
                }
            }
        }
        item {
            if (mode == Mode.DEMO) Panel {
                Heading("Two-user simulation")
                Text("Choose a sender. After delivery, switch users to read the reconstructed message.")
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = { demo("Alice") }) { Text("Open as Alice") }
                    OutlinedButton(onClick = { demo("Bob") }) { Text("Open as Bob") }
                }
            } else Panel {
                Heading("Carrier conversations")
                Text("Exchange and verify public keys before sending. Each segment may incur carrier charges.")
                Button(onClick = newSms) { Text("New conversation") }
            }
        }
        item { Heading("Conversations") }
        if (conversations.isEmpty()) item { Text("Your conversations will appear here.") }
        items(conversations.sortedByDescending { latest[it.id]?.message?.createdAt ?: 0L }, key = Conversation::id) { chat ->
            val preview = latest[chat.id]
            Card(Modifier.fillMaxWidth().clickable { open(chat) }) {
                Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(5.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(if (mode == Mode.DEMO) "${chat.owner}  →  ${chat.peer}" else chat.peer,
                            Modifier.weight(1f), style = MaterialTheme.typography.titleMedium)
                        preview?.let { Text(date(it.message.createdAt), style = MaterialTheme.typography.labelSmall) }
                    }
                    Text(preview?.body ?: preview?.message?.error ?: "No messages yet",
                        maxLines = 1, overflow = TextOverflow.Ellipsis)
                    preview?.let { Text(it.message.status.label, style = MaterialTheme.typography.labelMedium) }
                }
            }
        }
    }
}

@Composable
private fun ColumnScope.Chat(
    chat: Conversation,
    messages: List<DisplayMessage>,
    profile: KeyProfile?,
    busy: Boolean,
    availability: String?,
    scenario: Scenario,
    contact: ContactKey?,
    switchUser: () -> Unit,
    configure: () -> Unit,
    manageKeys: () -> Unit,
    inspect: (String) -> Unit,
    send: (String, () -> Unit) -> Unit
) {
    var draft by remember(chat.id) { mutableStateOf("") }
    val list = rememberLazyListState()
    LaunchedEffect(chat.id, messages.size) {
        if (messages.isNotEmpty()) list.requestScrollToItem(messages.lastIndex)
    }
    Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 6.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(profile?.label ?: "Unavailable", Modifier.weight(1f), fontWeight = FontWeight.SemiBold)
            TextButton(onClick = configure) { Text("Encryption") }
            if (chat.mode == Mode.DEMO) TextButton(onClick = switchUser) { Text("Open as ${chat.peer}") }
        }
        if (chat.mode == Mode.DEMO) {
            Text("Sending as ${chat.owner}  ·  ${scenario.label}", style = MaterialTheme.typography.bodySmall)
        } else {
            val gate = when {
                contact == null -> "Recipient key missing"
                !contact.verified -> "Recipient fingerprint unverified"
                else -> null
            }
            if (gate != null) Row(verticalAlignment = Alignment.CenterVertically) {
                Text(gate, Modifier.weight(1f), color = MaterialTheme.colorScheme.error)
                TextButton(onClick = manageKeys) { Text("Manage keys") }
            }
            availability?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
        }
    }
    HorizontalDivider()
    if (messages.isEmpty()) Box(Modifier.weight(1f).fillMaxWidth().padding(16.dp), contentAlignment = Alignment.Center) {
        Text("Messages will appear here.")
    } else LazyColumn(
        Modifier.weight(1f).fillMaxWidth().padding(horizontal = 16.dp),
        state = list,
        verticalArrangement = Arrangement.spacedBy(10.dp),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(vertical = 12.dp)
    ) {
        items(messages, key = { it.message.rowId }) { display ->
            val message = display.message
            Column(Modifier.fillMaxWidth(),
                horizontalAlignment = if (message.outgoing) Alignment.End else Alignment.Start) {
                Card(
                    Modifier.fillMaxWidth(0.88f).clickable { inspect(message.rowId) },
                    colors = CardDefaults.cardColors(containerColor =
                        if (message.outgoing) MaterialTheme.colorScheme.primaryContainer
                        else MaterialTheme.colorScheme.surfaceVariant)
                ) {
                    Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        SelectionContainer { Text(display.body ?: message.error ?: "History unavailable") }
                        if (display.body != null) message.error?.let {
                            Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                        }
                        val protection = if (!message.secure) "Demo" else if (message.status == Status.DECRYPTION_FAILED) {
                            "Ciphertext"
                        } else if (message.outgoing) "Encrypted" else "Decrypted"
                        Text("$protection  ·  ${message.status.label}  ·  ${date(message.createdAt)}",
                            style = MaterialTheme.typography.labelSmall)
                    }
                }
            }
        }
    }
    val bytes = draft.encodeToByteArray().size
    val keyboard = LocalSoftwareKeyboardController.current
    val canSend = chat.mode == Mode.DEMO || (availability == null && contact?.verified == true)
    Row(
        Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 8.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        OutlinedTextField(draft, { draft = it.take(2048) }, Modifier.weight(1f).heightIn(max = 145.dp),
            label = { Text("Message") }, supportingText = { Text("$bytes / ${SmsProtocol.maxPlaintextBytes} bytes") },
            isError = bytes > SmsProtocol.maxPlaintextBytes, maxLines = 4)
        Button(enabled = !busy && canSend && profile != null && draft.isNotBlank() &&
            bytes <= SmsProtocol.maxPlaintextBytes, onClick = {
            val sent = draft
            keyboard?.hide()
            send(sent) { if (draft == sent) draft = "" }
        }) { Text("Send") }
    }
}

@Composable
private fun Settings(
    mode: Mode,
    profiles: List<KeyProfile>,
    selected: KeyProfile?,
    select: (KeyProfile) -> Unit,
    scenario: Scenario,
    setScenario: (Scenario) -> Unit,
    availability: String?,
    requestSms: () -> Unit
) = ScrollPage {
    Panel {
        Heading("Encryption configuration")
        Text(if (mode == Mode.DEMO) "RSA and ECC profiles are simulated with an insecure test transform."
        else "The reference adapter uses AES-256-GCM with RSA-OAEP or ECDH and HKDF.")
        if (selected != null) Picker("Algorithm & key profile", selected, profiles, KeyProfile::label, select)
        else Text("Secure implementation unavailable on this device.")
        if (mode == Mode.SMS && KeyProfile.P256 !in profiles) Text("Keystore ECDH requires Android 12 or newer.")
    }
    if (mode == Mode.DEMO) Panel {
        Heading("Simulation behavior")
        Picker("Delivery scenario", scenario, Scenario.entries, Scenario::label, setScenario)
    } else Panel {
        Heading("SMS access")
        Text(availability ?: "Sending permission and a default SMS subscription are available.")
        Text("Android or the installer may restrict SMS permissions. Grant both send and receive access for two-way messaging.")
        Button(onClick = requestSms) { Text("Request SMS permissions") }
    }
}

@Composable
private fun Keys(inbox: Inbox, model: MessagingViewModel, busy: Boolean, share: (String) -> Unit) = ScrollPage {
    val profiles = model.profiles(Mode.SMS)
    var profile by rememberSaveable { mutableStateOf(KeyProfile.RSA_2048) }
    var peer by rememberSaveable { mutableStateOf("") }
    var publicKey by rememberSaveable { mutableStateOf("") }
    var verify by remember { mutableStateOf<ContactKey?>(null) }
    Panel {
        Heading("My public keys")
        Text("Private keys stay in Android Keystore. Share the public key and compare fingerprints through a trusted channel.")
        if (profiles.isEmpty()) {
            Text("Secure key generation is unavailable.")
        } else {
            val selected = profile.takeIf { it in profiles } ?: profiles.first()
            Picker("Key profile", selected, profiles, KeyProfile::label) { profile = it }
            val current = inbox.identities.firstOrNull { it.profile == selected }
            if (current == null) Button(onClick = { model.generate(selected) }, enabled = !busy) { Text("Generate key") }
            else {
                Fingerprint(current.spki)
                Button(onClick = { share(model.share(current)) }) { Text("Share public key") }
            }
        }
    }
    Panel {
        Heading("Import a recipient key")
        OutlinedTextField(peer, { peer = it.take(32) }, Modifier.fillMaxWidth(), label = { Text("International phone number") },
            singleLine = true, keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Phone))
        OutlinedTextField(publicKey, { publicKey = it.take(1100) }, Modifier.fillMaxWidth(),
            label = { Text("SSK1 public key") }, minLines = 2, maxLines = 4)
        Button(enabled = !busy && peer.isNotBlank() && publicKey.isNotBlank(),
            onClick = { model.import(peer, publicKey) { publicKey = "" } }) { Text("Import key") }
    }
    if (inbox.contacts.isEmpty()) Text("No recipient keys imported.")
    inbox.contacts.forEach { key ->
        Panel {
            Heading("${key.peer}  ·  ${key.profile.label}")
            Fingerprint(key.spki)
            Text(if (key.verified) "Fingerprint verified" else "Unverified recipient key")
            if (!key.verified) OutlinedButton(enabled = !busy, onClick = { verify = key }) { Text("Verify fingerprint") }
        }
    }
    verify?.let { key ->
        AlertDialog(
            onDismissRequest = { verify = null },
            title = { Text("Confirm fingerprint comparison") },
            text = { Column {
                Text("Compare this fingerprint with the recipient through a trusted channel.")
                Fingerprint(key.spki)
            } },
            confirmButton = { Button(onClick = { model.verify(key); verify = null }) { Text("Fingerprint matches") } },
            dismissButton = { TextButton(onClick = { verify = null }) { Text("Cancel") } }
        )
    }
}

@Composable
private fun Diagnostics(messages: List<DisplayMessage>, requested: String?) = ScrollPage {
    var selected by rememberSaveable(requested) { mutableStateOf(requested) }
    val entries = messages.asReversed()
    val item = entries.firstOrNull { it.message.rowId == selected } ?: entries.firstOrNull()
    if (item == null) {
        Panel {
            Heading("Message diagnostics")
            Text("Send or receive a message to inspect actual timings, sizes and transport state.")
        }
    } else {
        Panel {
            Heading("Message diagnostics")
            Picker("Message", item, entries, {
                val msg = it.message
                "${if (msg.outgoing) "Sent" else "Received"} · ${date(msg.createdAt)} · ${msg.wireId.take(8)}"
            }) { selected = it.message.rowId }
            val message = item.message
            val metrics = message.diagnostics
            Metric("Profile", metrics.profile.label)
            Metric("Result", message.status.label)
            Metric("Protection", if (message.secure) "Hybrid v1" else "Demo transform")
            HorizontalDivider()
            Metric("Encryption", duration(metrics.encryptionNanos))
            Metric("Decryption", duration(metrics.decryptionNanos))
            Metric("Plaintext", metrics.plaintextBytes?.let { "$it bytes" } ?: "Unavailable")
            Metric("Wire envelope", "${metrics.payloadBytes} bytes")
            Metric("SMS segments", metrics.segments.toString())
            message.error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            Text("Recipient fingerprint", style = MaterialTheme.typography.labelMedium)
            SelectionContainer { Text(message.fingerprint, fontFamily = FontFamily.Monospace) }
        }
    }
}

@Composable
private fun Metric(label: String, value: String) {
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(label, Modifier.weight(1f), color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, fontWeight = FontWeight.Medium)
    }
}

@Composable
private fun Fingerprint(key: ByteArray) {
    SelectionContainer { Text(fingerprintText(fingerprint(key)), fontFamily = FontFamily.Monospace) }
}

@Composable
private fun Heading(text: String) {
    Text(text, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold)
}

@Composable
private fun Panel(content: @Composable ColumnScope.() -> Unit) {
    Card(Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp), content = content)
    }
}

@Composable
private fun ScrollPage(content: @Composable ColumnScope.() -> Unit) {
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp), content = content
    )
}

@Composable
private fun <T> Picker(label: String, current: T, options: List<T>, name: (T) -> String, select: (T) -> Unit) {
    var expanded by remember { mutableStateOf(false) }
    Column {
        Text(label, style = MaterialTheme.typography.labelMedium)
        Box {
            OutlinedButton(onClick = { expanded = true }) { Text(name(current) + "  ▾") }
            DropdownMenu(expanded, { expanded = false }, Modifier.heightIn(max = 360.dp)) {
                options.forEach { option ->
                    DropdownMenuItem(text = { Text(name(option)) }, onClick = { select(option); expanded = false })
                }
            }
        }
    }
}

private fun modeLabel(mode: Mode) = if (mode == Mode.DEMO) "Offline demo" else "Carrier SMS"
private fun date(time: Long) = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(Date(time))
private fun duration(nanos: Long?) = nanos?.let { String.format(Locale.US, "%.3f ms", it / 1_000_000.0) } ?: "Unavailable"
