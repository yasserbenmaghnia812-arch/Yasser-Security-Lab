package com.yasser.securitylab

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL

private data class LocalChatTurn(val role: String, val content: String)

/**
 * Connects to a user-provided, loopback-only OpenAI-compatible inference server.
 *
 * This is not a direct LocalMind SDK integration. LocalMind must expose an
 * OpenAI-compatible endpoint or the user must run a local bridge/server.
 * No cloud endpoint or paid model provider is contacted by this panel.
 */
@Composable
fun LocalAiChatPanel() {
    val scope = rememberCoroutineScope()
    var baseUrl by remember { mutableStateOf("http://127.0.0.1:11434/v1") }
    var apiKey by remember { mutableStateOf("") }
    var modelId by remember { mutableStateOf("") }
    var prompt by remember { mutableStateOf("") }
    var conversation by remember {
        mutableStateOf(
            listOf(
                LocalChatTurn(
                    "assistant",
                    "هذه واجهة لنموذج محلي. شغّل خادم استدلال متوافقاً مع OpenAI على الهاتف، ثم أدخل عنوانه ومعرّف النموذج."
                )
            )
        )
    }
    var busy by remember { mutableStateOf(false) }

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Text("محادثة نموذج محلي", fontWeight = FontWeight.Bold)
            Text(
                "يتصل بخادم استدلال محلي متوافق مع OpenAI فقط. لا يوجد اتصال مباشر مدمج مع LocalMind حالياً، ولا تُرسل الرسائل إلى خدمة سحابية."
            )
            OutlinedTextField(
                value = baseUrl,
                onValueChange = { baseUrl = it },
                label = { Text("عنوان الخادم المحلي") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )
            OutlinedTextField(
                value = modelId,
                onValueChange = { modelId = it },
                label = { Text("معرّف النموذج") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )
            OutlinedTextField(
                value = apiKey,
                onValueChange = { apiKey = it },
                label = { Text("مفتاح الخادم (اختياري)") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password)
            )
            conversation.takeLast(8).forEach { turn ->
                Text(
                    text = (if (turn.role == "user") "أنت: " else "المساعد: ") + turn.content,
                    fontWeight = if (turn.role == "assistant") FontWeight.Normal else FontWeight.SemiBold
                )
            }
            OutlinedTextField(
                value = prompt,
                onValueChange = { prompt = it },
                label = { Text("اكتب رسالتك") },
                modifier = Modifier.fillMaxWidth(),
                minLines = 2
            )
            Button(
                enabled = !busy && prompt.isNotBlank() && modelId.isNotBlank(),
                onClick = {
                    val endpoint = baseUrl.trim().trimEnd('/')
                    val selectedModel = modelId.trim()
                    val secret = apiKey.trim()
                    val question = prompt.trim()
                    val nextConversation = conversation + LocalChatTurn("user", question)
                    conversation = nextConversation
                    prompt = ""
                    busy = true
                    scope.launch {
                        try {
                            val reply = withContext(Dispatchers.IO) {
                                completeLocalChat(endpoint, selectedModel, secret, nextConversation)
                            }
                            conversation = nextConversation + LocalChatTurn("assistant", reply)
                        } catch (error: Exception) {
                            val detail = error.message ?: "خطأ غير معروف"
                            conversation = nextConversation + LocalChatTurn(
                                "assistant",
                                "تعذر الاتصال بالخادم المحلي: $detail"
                            )
                        } finally {
                            busy = false
                        }
                    }
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(if (busy) "جارٍ التفكير..." else "إرسال")
            }
            Text(if (busy) "الخادم المحلي يعالج المحادثة..." else "المحادثة محفوظة مؤقتاً أثناء بقاء هذه الشاشة مفتوحة.")
        }
    }
}

private fun completeLocalChat(
    baseUrl: String,
    modelId: String,
    apiKey: String,
    history: List<LocalChatTurn>
): String {
    val parsed = URL(baseUrl)
    val host = parsed.host.lowercase()
    if (
        parsed.protocol != "http" ||
        host !in setOf("127.0.0.1", "localhost", "::1", "[::1]") ||
        parsed.userInfo != null ||
        parsed.query != null ||
        parsed.ref != null
    ) {
        throw IOException("يسمح هذا الإصدار بخادم محلي فقط: 127.0.0.1 أو localhost أو ::1.")
    }

    val endpointPath = parsed.path.trimEnd('/') + "/chat/completions"
    val endpoint = URL(parsed.protocol, parsed.host, parsed.port, endpointPath)
    val connection = (endpoint.openConnection() as HttpURLConnection).apply {
        requestMethod = "POST"
        connectTimeout = 10000
        readTimeout = 120000
        doOutput = true
        setRequestProperty("Content-Type", "application/json")
        if (apiKey.isNotBlank()) {
            setRequestProperty("Authorization", "Bearer $apiKey")
        }
    }
    try {
        val messages = JSONArray()
        history.forEach { turn ->
            messages.put(
                JSONObject()
                    .put("role", turn.role)
                    .put("content", turn.content)
            )
        }
        val body = JSONObject()
            .put("model", modelId)
            .put("messages", messages)
            .put("stream", false)
            .toString()
            .toByteArray(Charsets.UTF_8)
        connection.outputStream.use { it.write(body) }
        val status = connection.responseCode
        val stream = if (status in 200..299) connection.inputStream else connection.errorStream
        val responseText = stream?.bufferedReader()?.use { it.readText() }.orEmpty()
        if (status !in 200..299) {
            val detail = try {
                JSONObject(responseText).optString("error", responseText)
            } catch (_: Exception) {
                responseText
            }
            throw IOException("HTTP $status: $detail")
        }
        val content = JSONObject(responseText)
            .getJSONArray("choices")
            .getJSONObject(0)
            .getJSONObject("message")
            .optString("content")
        if (content.isBlank()) throw IOException("أعاد الخادم رداً فارغاً.")
        return content
    } finally {
        connection.disconnect()
    }
}
